// Command capacity runs opt-in, controlled-runner scale profiles. It is kept
// separate from the short benchmark because the 10k-tunnel profile consumes
// thousands of sockets and must not run on every developer machine.
package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime"
	"sort"
	"time"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/client"
	"github.com/wirerift/wirerift/internal/mux"
	"github.com/wirerift/wirerift/internal/proto"
	"github.com/wirerift/wirerift/internal/server"
)

const idleTunnelMemoryTarget = 50 * 1024

func main() {
	profile := flag.String("profile", "", "profile to run: streams, tunnels, or all")
	streamCount := flag.Int("streams", 257, "concurrent mux streams to keep open")
	tunnelCount := flag.Int("tunnels", 10_000, "idle HTTP tunnels to create")
	tunnelsPerSession := flag.Int("tunnels-per-session", 10, "tunnels created by each client session")
	flag.Parse()

	if *profile == "" {
		fmt.Fprintln(os.Stderr, "capacity failed: -profile streams, tunnels, or all is required")
		os.Exit(2)
	}
	if *streamCount < 257 || *tunnelCount < 1 || *tunnelsPerSession < 1 {
		fmt.Fprintln(os.Stderr, "capacity failed: streams must be >=257 and tunnel counts must be positive")
		os.Exit(2)
	}

	var err error
	switch *profile {
	case "streams":
		err = runStreams(*streamCount)
	case "tunnels":
		err = runTunnels(*tunnelCount, *tunnelsPerSession)
	case "all":
		if err = runStreams(*streamCount); err == nil {
			err = runTunnels(*tunnelCount, *tunnelsPerSession)
		}
	default:
		err = fmt.Errorf("unknown profile %q", *profile)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "capacity failed: %v\n", err)
		os.Exit(1)
	}
}

func runStreams(count int) error {
	left, right := net.Pipe()
	clientMux := mux.New(left, mux.DefaultConfig())
	serverMux := mux.New(right, mux.DefaultConfig())
	defer clientMux.Close()
	defer serverMux.Close()
	go clientMux.Run()
	go serverMux.Run()

	local := make([]*mux.Stream, 0, count)
	remote := make([]*mux.Stream, 0, count)
	latencies := make([]time.Duration, 0, count)
	for i := 0; i < count; i++ {
		start := time.Now()
		stream, err := clientMux.OpenStream()
		if err != nil {
			return fmt.Errorf("open stream %d: %w", i, err)
		}
		openFrame, err := proto.EncodeJSONPayload(proto.FrameStreamOpen, stream.ID(), &proto.StreamOpen{Protocol: "capacity"})
		if err != nil {
			return fmt.Errorf("encode stream %d announcement: %w", i, err)
		}
		if err := clientMux.GetFrameWriter().Write(openFrame); err != nil {
			return fmt.Errorf("announce stream %d: %w", i, err)
		}
		peer, err := serverMux.AcceptStream()
		if err != nil {
			return fmt.Errorf("accept stream %d: %w", i, err)
		}
		local = append(local, stream)
		remote = append(remote, peer)
		latencies = append(latencies, time.Since(start))
	}
	if len(local) <= 256 || len(remote) != len(local) {
		return fmt.Errorf("concurrent streams=%d, want >256 mirrored streams", len(local))
	}
	fmt.Printf("CAPACITY_STREAMS_OK streams=%d open_p95=%s open_p99=%s\n",
		len(local), percentile(latencies, 95), percentile(latencies, 99))
	return nil
}

func runTunnels(target, perSession int) error {
	sessions := (target + perSession - 1) / perSession
	tokens := &auth.TokenFile{}
	secrets := make([]string, 0, sessions)
	for i := 0; i < sessions; i++ {
		secret, _, err := tokens.CreateToken(auth.CreateOptions{
			Account:     fmt.Sprintf("capacity%05d", i),
			Name:        "capacity",
			MaxTunnels:  perSession,
			MaxSessions: 1,
			RateLimit:   perSession,
		})
		if err != nil {
			return fmt.Errorf("create token %d: %w", i, err)
		}
		secrets = append(secrets, secret)
	}

	authManager := auth.NewManager("capacity-bootstrap-only")
	authManager.ApplyTokenFile(tokens)
	cfg := server.DefaultConfig()
	cfg.ControlAddr = "127.0.0.1:0"
	cfg.HTTPAddr = ""
	cfg.HTTPSAddr = ""
	cfg.TCPAddrRange = "30000-30009"
	cfg.MaxTunnelsPerSession = perSession
	cfg.AuthManager = authManager
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := server.New(cfg, quiet)
	if err := srv.Start(); err != nil {
		return fmt.Errorf("start server: %w", err)
	}
	defer srv.Stop()

	clients := make([]*client.Client, 0, sessions)
	defer func() {
		for i := len(clients) - 1; i >= 0; i-- {
			_ = clients[i].Close()
		}
	}()
	for i, secret := range secrets {
		cfg := client.DefaultConfig()
		cfg.ServerAddr = srv.ControlAddr()
		cfg.Token = secret
		cfg.Reconnect = false
		c := client.New(cfg, quiet)
		if err := c.Connect(); err != nil {
			return fmt.Errorf("connect session %d: %w", i, err)
		}
		clients = append(clients, c)
	}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	latencies := make([]time.Duration, 0, target)
	created := 0
	start := time.Now()
	for sessionIndex, c := range clients {
		for tunnelIndex := 0; tunnelIndex < perSession && created < target; tunnelIndex++ {
			requestStart := time.Now()
			_, err := c.HTTP("127.0.0.1:1", client.WithSubdomain(
				fmt.Sprintf("capacity-%05d-%03d", sessionIndex, tunnelIndex)))
			if err != nil {
				return fmt.Errorf("create tunnel %d: %w", created, err)
			}
			latencies = append(latencies, time.Since(requestStart))
			created++
		}
	}
	if created != target {
		return fmt.Errorf("created %d tunnels, want %d", created, target)
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if after.Alloc < before.Alloc {
		return fmt.Errorf("live heap decreased during tunnel profile; measurement is invalid")
	}
	bytesPerTunnel := (after.Alloc - before.Alloc) / uint64(created)
	if bytesPerTunnel >= idleTunnelMemoryTarget {
		return fmt.Errorf("live bytes per idle tunnel=%d, target <%d", bytesPerTunnel, idleTunnelMemoryTarget)
	}

	fmt.Printf("CAPACITY_TUNNELS_OK tunnels=%d sessions=%d elapsed=%s setup_p95=%s setup_p99=%s live_bytes_per_idle_tunnel=%d\n",
		created, len(clients), time.Since(start).Round(time.Millisecond), percentile(latencies, 95),
		percentile(latencies, 99), bytesPerTunnel)
	return nil
}

func percentile(values []time.Duration, pct int) time.Duration {
	copyOfValues := append([]time.Duration(nil), values...)
	sort.Slice(copyOfValues, func(i, j int) bool { return copyOfValues[i] < copyOfValues[j] })
	index := len(copyOfValues) * pct / 100
	if index >= len(copyOfValues) {
		index = len(copyOfValues) - 1
	}
	return copyOfValues[index].Round(time.Microsecond)
}
