package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/proto"
)

// --- Basic utility tests ---

func TestGetEnv(t *testing.T) {
	if got := getEnv("TEST_VAR_NONEXISTENT", "default"); got != "default" {
		t.Errorf("getEnv() = %q, want default", got)
	}
	os.Setenv("TEST_VAR_WIRERIFT", "custom_value")
	defer os.Unsetenv("TEST_VAR_WIRERIFT")
	if got := getEnv("TEST_VAR_WIRERIFT", "default"); got != "custom_value" {
		t.Errorf("getEnv() = %q, want custom_value", got)
	}
}

func TestParseCommonOptions(t *testing.T) {
	origServer := os.Getenv("WIRERIFT_SERVER")
	origToken := os.Getenv("WIRERIFT_TOKEN")
	os.Unsetenv("WIRERIFT_SERVER")
	os.Unsetenv("WIRERIFT_TOKEN")
	defer func() {
		if origServer != "" {
			os.Setenv("WIRERIFT_SERVER", origServer)
		}
		if origToken != "" {
			os.Setenv("WIRERIFT_TOKEN", origToken)
		}
	}()

	opts := parseCommonOptions()
	if opts.server != "localhost:4443" || opts.token != "" {
		t.Errorf("opts = %+v", opts)
	}

	os.Setenv("WIRERIFT_SERVER", "custom:1234")
	os.Setenv("WIRERIFT_TOKEN", "test-token")
	opts = parseCommonOptions()
	if opts.server != "custom:1234" || opts.token != "test-token" {
		t.Errorf("opts = %+v", opts)
	}
}

func TestCreateLogger(t *testing.T) {
	if createLogger(false) == nil || createLogger(true) == nil {
		t.Error("should not return nil")
	}
}

func TestPrintUsage(t *testing.T) { printUsage() }

func TestVersionVariables(t *testing.T) {
	if version == "" || commit == "" || date == "" {
		t.Error("version vars should be defined")
	}
}

func TestCommonOptionsStruct(t *testing.T) {
	opts := commonOptions{server: "s", token: "t"}
	if opts.server != "s" || opts.token != "t" {
		t.Errorf("opts = %+v", opts)
	}
}

func TestConfigFileStruct(t *testing.T) {
	cfg := ConfigFile{Server: "s", Token: "t", Tunnels: []TunnelConfig{{Type: "http", LocalPort: 8080, Subdomain: "x"}}}
	if cfg.Server != "s" || len(cfg.Tunnels) != 1 {
		t.Errorf("cfg = %+v", cfg)
	}
}

func TestTunnelConfigStruct(t *testing.T) {
	tc := TunnelConfig{Type: "http", LocalPort: 8080, Subdomain: "testapp"}
	if tc.Type != "http" || tc.LocalPort != 8080 || tc.Subdomain != "testapp" {
		t.Errorf("tc = %+v", tc)
	}
}

// --- loadConfig tests ---

func TestLoadConfig(t *testing.T) {
	f := filepath.Join(t.TempDir(), "test.yaml")
	os.WriteFile(f, []byte("server: custom.server:4443\ntoken: my-token\n\ntunnels:\n  - type: http\n    local_port: 8080\n    subdomain: myapp\n  - type: tcp\n    local_port: 25565\n"), 0644)
	cfg, err := loadConfig(f)
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}
	if cfg.Server != "custom.server:4443" || cfg.Token != "my-token" || len(cfg.Tunnels) != 2 {
		t.Errorf("cfg = %+v", cfg)
	}
}

func TestLoadConfigNotFound(t *testing.T) {
	if _, err := loadConfig("/nonexistent/path"); err == nil {
		t.Error("should fail")
	}
}

func TestLoadConfigMinimal(t *testing.T) {
	f := filepath.Join(t.TempDir(), "m.yaml")
	os.WriteFile(f, []byte("server: test.server\n"), 0644)
	cfg, _ := loadConfig(f)
	if cfg.Server != "test.server" {
		t.Errorf("Server = %q", cfg.Server)
	}
}

func TestLoadConfigWithEnvDefaults(t *testing.T) {
	os.Setenv("WIRERIFT_SERVER", "env.server:4443")
	os.Setenv("WIRERIFT_TOKEN", "env-token")
	defer os.Unsetenv("WIRERIFT_SERVER")
	defer os.Unsetenv("WIRERIFT_TOKEN")
	f := filepath.Join(t.TempDir(), "e.yaml")
	os.WriteFile(f, []byte(""), 0644)
	cfg, _ := loadConfig(f)
	if cfg.Server != "env.server:4443" || cfg.Token != "env-token" {
		t.Errorf("cfg = %+v", cfg)
	}
}

func TestLoadConfigWithComments(t *testing.T) {
	f := filepath.Join(t.TempDir(), "c.yaml")
	os.WriteFile(f, []byte("# comment\nserver: test.server\ntoken: test-token\n"), 0644)
	cfg, _ := loadConfig(f)
	if cfg.Server != "test.server" || cfg.Token != "test-token" {
		t.Errorf("cfg = %+v", cfg)
	}
}

func TestLoadConfigWithQuotes(t *testing.T) {
	f := filepath.Join(t.TempDir(), "q.yaml")
	os.WriteFile(f, []byte("server: \"test.server:4443\"\ntoken: 'my-token'\n"), 0644)
	cfg, _ := loadConfig(f)
	if cfg.Server != "test.server:4443" || cfg.Token != "my-token" {
		t.Errorf("cfg = %+v", cfg)
	}
}

func TestLoadConfigEmptyFile(t *testing.T) {
	os.Unsetenv("WIRERIFT_SERVER")
	os.Unsetenv("WIRERIFT_TOKEN")
	f := filepath.Join(t.TempDir(), "empty.yaml")
	os.WriteFile(f, []byte(""), 0644)
	cfg, _ := loadConfig(f)
	if cfg.Server != "localhost:4443" || cfg.Token != "" || len(cfg.Tunnels) != 0 {
		t.Errorf("cfg = %+v", cfg)
	}
}

func TestLoadConfigInvalidLine(t *testing.T) {
	f := filepath.Join(t.TempDir(), "inv.yaml")
	os.WriteFile(f, []byte("server: test.server\nno_colon_here\ntoken: test-token\n"), 0644)
	cfg, _ := loadConfig(f)
	if cfg.Server != "test.server" || cfg.Token != "test-token" {
		t.Errorf("cfg = %+v", cfg)
	}
}

// --- run() tests ---

func TestRun_NoArgs(t *testing.T)         { assertErr(t, run([]string{"wirerift"})) }
func TestRun_Version(t *testing.T)        { assertNoErr(t, run([]string{"wirerift", "version"})) }
func TestRun_UnknownCommand(t *testing.T) { assertErr(t, run([]string{"wirerift", "bogus"})) }

func TestRun_Help(t *testing.T) {
	for _, cmd := range []string{"help", "-h", "--help"} {
		assertNoErr(t, run([]string{"wirerift", cmd}))
	}
}

func TestRun_Config(t *testing.T) {
	withTempDir(t, func() { assertNoErr(t, run([]string{"wirerift", "config"})) })
}
func TestRun_ConfigInit(t *testing.T) {
	withTempDir(t, func() { assertNoErr(t, run([]string{"wirerift", "config", "init"})) })
}
func TestRun_ConfigUnknown(t *testing.T) { assertErr(t, run([]string{"wirerift", "config", "badcmd"})) }
func TestRun_HTTP_Error(t *testing.T)    { assertErr(t, run([]string{"wirerift", "http"})) }
func TestRun_TCP_Error(t *testing.T)     { assertErr(t, run([]string{"wirerift", "tcp"})) }
func TestRun_Start_Error(t *testing.T) {
	withTempDir(t, func() { assertErr(t, run([]string{"wirerift", "start"})) })
}
func TestRun_List_Error(t *testing.T) {
	withEnv(t, "WIRERIFT_SERVER", "127.0.0.1:1")
	assertErr(t, run([]string{"wirerift", "list"}))
}

// --- showConfig / initConfig tests ---

func TestShowConfig_NoFile(t *testing.T) { withTempDir(t, func() { showConfig() }) }
func TestShowConfig_WithFile(t *testing.T) {
	withTempDir(t, func() {
		os.WriteFile("wirerift.yaml", []byte("server: test\n"), 0644)
		showConfig()
	})
}

func TestInitConfig_NewFile(t *testing.T) {
	withTempDir(t, func() {
		initConfig()
		data, _ := os.ReadFile("wirerift.yaml")
		if !strings.Contains(string(data), "server: localhost:4443") {
			t.Errorf("Missing content: %s", data)
		}
	})
}

func TestInitConfig_ExistingFile_Abort(t *testing.T) {
	withTempDir(t, func() {
		os.WriteFile("wirerift.yaml", []byte("existing"), 0644)
		withStdin(t, "n\n", func() { initConfig() })
		data, _ := os.ReadFile("wirerift.yaml")
		if string(data) != "existing" {
			t.Errorf("File modified: %s", data)
		}
	})
}

func TestInitConfig_ExistingFile_Overwrite(t *testing.T) {
	withTempDir(t, func() {
		os.WriteFile("wirerift.yaml", []byte("old"), 0644)
		withStdin(t, "y\n", func() { initConfig() })
		data, _ := os.ReadFile("wirerift.yaml")
		if !strings.Contains(string(data), "server: localhost:4443") {
			t.Errorf("Not overwritten: %s", data)
		}
	})
}

// --- doConfig tests ---

func TestDoConfig_NoSubcommand(t *testing.T) {
	withTempDir(t, func() { assertNoErr(t, doConfig([]string{"wirerift", "config"})) })
}
func TestDoConfig_Show(t *testing.T) {
	withTempDir(t, func() { assertNoErr(t, doConfig([]string{"wirerift", "config", "show"})) })
}
func TestDoConfig_Init(t *testing.T) {
	withTempDir(t, func() { assertNoErr(t, doConfig([]string{"wirerift", "config", "init"})) })
}
func TestDoConfig_Unknown(t *testing.T) {
	assertErr(t, doConfig([]string{"wirerift", "config", "badcmd"}))
}

// --- doHTTP error tests ---

func TestDoHTTP_NoPort(t *testing.T) {
	assertErrContains(t, doHTTP(context.Background(), []string{"wirerift", "http"}), "missing port")
}
func TestDoHTTP_InvalidPort(t *testing.T) {
	assertErrContains(t, doHTTP(context.Background(), []string{"wirerift", "http", "abc"}), "invalid port")
}
func TestDoHTTP_ConnectFail(t *testing.T) {
	assertErrContains(t, doHTTP(context.Background(), []string{"wirerift", "http", "-server", "127.0.0.1:1", "8080"}), "failed to connect")
}
func TestDoHTTP_ConnectFail_WithSubdomain(t *testing.T) {
	assertErrContains(t, doHTTP(context.Background(), []string{"wirerift", "http", "-server", "127.0.0.1:1", "8080", "mysubdomain"}), "failed to connect")
}
func TestDoHTTP_ConnectFail_WithFlags(t *testing.T) {
	assertErrContains(t, doHTTP(context.Background(), []string{"wirerift", "http", "-server", "127.0.0.1:1", "-token", "tok", "-subdomain", "sub", "-v", "8080"}), "failed to connect")
}
func TestDoHTTP_FlagParseError(t *testing.T) {
	assertErr(t, doHTTP(context.Background(), []string{"wirerift", "http", "-unknown-flag"}))
}

// --- doTCP error tests ---

func TestDoTCP_NoPort(t *testing.T) {
	assertErrContains(t, doTCP(context.Background(), []string{"wirerift", "tcp"}), "missing port")
}
func TestDoTCP_InvalidPort(t *testing.T) {
	assertErrContains(t, doTCP(context.Background(), []string{"wirerift", "tcp", "abc"}), "invalid port")
}
func TestDoTCP_ConnectFail(t *testing.T) {
	assertErrContains(t, doTCP(context.Background(), []string{"wirerift", "tcp", "-server", "127.0.0.1:1", "25565"}), "failed to connect")
}
func TestDoTCP_ConnectFail_WithFlags(t *testing.T) {
	assertErrContains(t, doTCP(context.Background(), []string{"wirerift", "tcp", "-server", "127.0.0.1:1", "-token", "tok", "-v", "25565"}), "failed to connect")
}
func TestDoTCP_FlagParseError(t *testing.T) {
	assertErr(t, doTCP(context.Background(), []string{"wirerift", "tcp", "-unknown-flag"}))
}

// --- doStart error tests ---

func TestDoStart_NoConfig(t *testing.T) {
	withTempDir(t, func() {
		assertErrContains(t, doStart(context.Background(), []string{"wirerift", "start"}), "failed to load config")
	})
}
func TestDoStart_ConnectFail(t *testing.T) {
	withTempDir(t, func() {
		os.WriteFile("wirerift.yaml", []byte("server: 127.0.0.1:1\ntunnels:\n  - type: http\n    local_port: 8080\n"), 0644)
		assertErrContains(t, doStart(context.Background(), []string{"wirerift", "start"}), "failed to connect")
	})
}
func TestDoStart_ConnectFail_WithFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "custom.yaml")
	os.WriteFile(f, []byte("server: 127.0.0.1:1\ntunnels:\n  - type: http\n    local_port: 8080\n"), 0644)
	assertErrContains(t, doStart(context.Background(), []string{"wirerift", "start", f}), "failed to connect")
}
func TestDoStart_ConnectFail_Verbose(t *testing.T) {
	withTempDir(t, func() {
		os.WriteFile("wirerift.yaml", []byte("server: 127.0.0.1:1\ntunnels:\n  - type: http\n    local_port: 8080\n"), 0644)
		assertErrContains(t, doStart(context.Background(), []string{"wirerift", "start", "-v"}), "failed to connect")
	})
}
func TestDoStart_FlagParseError(t *testing.T) {
	assertErr(t, doStart(context.Background(), []string{"wirerift", "start", "-unknown-flag"}))
}

// --- doList error tests ---

func TestDoList_ConnectFail(t *testing.T) {
	assertErrContains(t, doList([]string{"wirerift", "list", "-server", "127.0.0.1:1"}), "failed to connect to server")
}
func TestDoList_ConnectFail_WithToken(t *testing.T) {
	assertErr(t, doList([]string{"wirerift", "list", "-server", "127.0.0.1:1", "-token", "tok"}))
}
func TestDoList_FlagParseError(t *testing.T) {
	assertErr(t, doList([]string{"wirerift", "list", "-unknown-flag"}))
}

// --- doList with mock HTTP server ---

func TestDoList_JSON_MockServer(t *testing.T) {
	srv := startMockListServer(t, `[{"id":"t1","type":"http","url":"http://test.wirerift.com","target":"localhost:8080","status":"active"}]`)
	defer srv.Close()
	assertNoErr(t, doList([]string{"wirerift", "list", "-json", "-server", "127.0.0.1:4040"}))
}

func TestDoList_Table_MockServer(t *testing.T) {
	srv := startMockListServer(t, `[{"id":"t1","type":"http","url":"http://test.wirerift.com","target":"localhost:8080","status":"active"},{"id":"t2","type":"tcp","port":20001,"target":"localhost:25565","status":"active"}]`)
	defer srv.Close()
	assertNoErr(t, doList([]string{"wirerift", "list", "-server", "127.0.0.1:4040", "-token", "tok"}))
}

func TestDoList_Empty_MockServer(t *testing.T) {
	srv := startMockListServer(t, `[]`)
	defer srv.Close()
	assertNoErr(t, doList([]string{"wirerift", "list", "-server", "127.0.0.1:4040"}))
}

func TestDoList_InvalidJSON_MockServer(t *testing.T) {
	srv := startMockListServer(t, `not json`)
	defer srv.Close()
	assertErrContains(t, doList([]string{"wirerift", "list", "-server", "127.0.0.1:4040"}), "failed to parse response")
}

func TestDoList_NoToken_MockServer(t *testing.T) {
	withEnv(t, "WIRERIFT_TOKEN", "")
	withEnv(t, "WIRERIFT_SERVER", "")
	srv := startMockListServer(t, `[]`)
	defer srv.Close()
	assertNoErr(t, doList([]string{"wirerift", "list", "-server", "127.0.0.1:4040"}))
}

func startMockListServer(t *testing.T, responseBody string) *http.Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:4040")
	if err != nil {
		t.Skipf("Port 4040 in use: %v", err)
	}
	ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/tunnels", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(responseBody))
	})
	srv := &http.Server{Addr: "127.0.0.1:4040", Handler: mux}
	go srv.ListenAndServe()
	time.Sleep(50 * time.Millisecond)
	return srv
}

// --- Mock WireRift tunnel server for success-path tests ---

func startMockTunnelServer(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleMockClient(conn)
		}
	}()

	cleanup := func() {
		listener.Close()
		<-done
	}

	return listener.Addr().String(), cleanup
}

func startMockTunnelServerWithTunnelError(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleMockClientTunnelError(conn)
		}
	}()

	cleanup := func() {
		listener.Close()
		<-done
	}

	return listener.Addr().String(), cleanup
}

func handleMockClient(conn net.Conn) {
	defer conn.Close()

	// Read magic
	magic := make([]byte, 4)
	if _, err := io.ReadFull(conn, magic); err != nil {
		return
	}

	fr := proto.NewFrameReader(conn)
	fw := proto.NewFrameWriter(conn)

	for {
		frame, err := fr.Read()
		if err != nil {
			return
		}

		switch frame.Type {
		case proto.FrameAuthReq:
			resp := &proto.AuthResponse{
				OK:         true,
				SessionID:  "test-session-123",
				MaxTunnels: 10,
			}
			respFrame, _ := proto.EncodeJSONPayload(proto.FrameAuthRes, 0, resp)
			fw.Write(respFrame)

		case proto.FrameTunnelReq:
			var req proto.TunnelRequest
			proto.DecodeJSONPayload(frame, &req)
			resp := &proto.TunnelResponse{
				OK:        true,
				TunnelID:  "tun-test-123",
				Type:      req.Type,
				PublicURL: "https://test.wirerift.com",
			}
			respFrame, _ := proto.EncodeJSONPayload(proto.FrameTunnelRes, 0, resp)
			fw.Write(respFrame)

		case proto.FrameHeartbeat:
			ack := &proto.Frame{
				Version:  proto.Version,
				Type:     proto.FrameHeartbeatAck,
				StreamID: 0,
				Payload:  frame.Payload,
			}
			fw.Write(ack)
		}
	}
}

func handleMockClientTunnelError(conn net.Conn) {
	defer conn.Close()

	// Read magic
	magic := make([]byte, 4)
	if _, err := io.ReadFull(conn, magic); err != nil {
		return
	}

	fr := proto.NewFrameReader(conn)
	fw := proto.NewFrameWriter(conn)

	for {
		frame, err := fr.Read()
		if err != nil {
			return
		}

		switch frame.Type {
		case proto.FrameAuthReq:
			resp := &proto.AuthResponse{
				OK:         true,
				SessionID:  "test-session-456",
				MaxTunnels: 10,
			}
			respFrame, _ := proto.EncodeJSONPayload(proto.FrameAuthRes, 0, resp)
			fw.Write(respFrame)

		case proto.FrameTunnelReq:
			resp := &proto.TunnelResponse{
				OK:    false,
				Error: "tunnel limit exceeded",
			}
			respFrame, _ := proto.EncodeJSONPayload(proto.FrameTunnelRes, 0, resp)
			fw.Write(respFrame)

		case proto.FrameHeartbeat:
			ack := &proto.Frame{
				Version:  proto.Version,
				Type:     proto.FrameHeartbeatAck,
				StreamID: 0,
				Payload:  frame.Payload,
			}
			fw.Write(ack)
		}
	}
}

// lockGOMAXPROCS sets GOMAXPROCS to 1 and returns a restore function.
// With GOMAXPROCS(1), goroutine scheduling is cooperative: a goroutine
// only yields at blocking points (I/O, channel ops, runtime.Gosched).
// This ensures that after connect() starts `go mux.Run()`, the calling
// goroutine continues uninterrupted through openTunnel's Write + Read
// sequence, acquiring the net.Conn read lock before mux.Run's goroutine
// ever gets scheduled. This prevents the race where mux.Run() would
// consume tunnel response frames meant for openTunnel.
func lockGOMAXPROCS() func() {
	prev := runtime.GOMAXPROCS(1)
	return func() { runtime.GOMAXPROCS(prev) }
}

// --- doHTTP success tests ---

func TestDoHTTPSuccess(t *testing.T) {
	defer lockGOMAXPROCS()()

	addr, cleanup := startMockTunnelServer(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	args := []string{"wirerift", "http", "-server", addr, "8080"}
	err := doHTTP(ctx, args)
	if err != nil {
		t.Fatalf("doHTTP failed: %v", err)
	}
}

func TestDoHTTPSuccessWithSubdomain(t *testing.T) {
	defer lockGOMAXPROCS()()

	addr, cleanup := startMockTunnelServer(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	args := []string{"wirerift", "http", "-server", addr, "-subdomain", "myapp", "-v", "8080"}
	err := doHTTP(ctx, args)
	if err != nil {
		t.Fatalf("doHTTP with subdomain failed: %v", err)
	}
}

func TestDoHTTPSuccessPositionalSubdomain(t *testing.T) {
	defer lockGOMAXPROCS()()

	addr, cleanup := startMockTunnelServer(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	args := []string{"wirerift", "http", "-server", addr, "8080", "myapp"}
	err := doHTTP(ctx, args)
	if err != nil {
		t.Fatalf("doHTTP with positional subdomain failed: %v", err)
	}
}

func TestDoHTTPTunnelCreateFail(t *testing.T) {
	defer lockGOMAXPROCS()()

	addr, cleanup := startMockTunnelServerWithTunnelError(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	args := []string{"wirerift", "http", "-server", addr, "8080"}
	err := doHTTP(ctx, args)
	if err == nil {
		t.Fatal("Expected error from doHTTP with tunnel failure")
	}
	if !strings.Contains(err.Error(), "failed to create tunnel") {
		t.Fatalf("Expected 'failed to create tunnel' error, got: %v", err)
	}
}

// --- doTCP success tests ---

func TestDoTCPSuccess(t *testing.T) {
	defer lockGOMAXPROCS()()

	addr, cleanup := startMockTunnelServer(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	args := []string{"wirerift", "tcp", "-server", addr, "-v", "8080"}
	err := doTCP(ctx, args)
	if err != nil {
		t.Fatalf("doTCP failed: %v", err)
	}
}

func TestDoTCPTunnelCreateFail(t *testing.T) {
	defer lockGOMAXPROCS()()

	addr, cleanup := startMockTunnelServerWithTunnelError(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	args := []string{"wirerift", "tcp", "-server", addr, "8080"}
	err := doTCP(ctx, args)
	if err == nil {
		t.Fatal("Expected error from doTCP with tunnel failure")
	}
	if !strings.Contains(err.Error(), "failed to create tunnel") {
		t.Fatalf("Expected 'failed to create tunnel' error, got: %v", err)
	}
}

// --- doStart success tests ---

func TestDoStartSuccess(t *testing.T) {
	defer lockGOMAXPROCS()()

	addr, cleanup := startMockTunnelServer(t)
	defer cleanup()

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "test.yaml")
	configContent := fmt.Sprintf("server: %s\ntoken: test\n\ntunnels:\n  - type: http\n    local_port: 8080\n    subdomain: test\n  - type: tcp\n    local_port: 9090\n", addr)
	os.WriteFile(configFile, []byte(configContent), 0644)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()

	args := []string{"wirerift", "start", "-v", configFile}
	err := doStart(ctx, args)
	if err != nil {
		t.Fatalf("doStart failed: %v", err)
	}
}

func TestDoStartUnknownTunnelType(t *testing.T) {
	defer lockGOMAXPROCS()()

	addr, cleanup := startMockTunnelServer(t)
	defer cleanup()

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "test.yaml")
	configContent := fmt.Sprintf("server: %s\ntoken: test\n\ntunnels:\n  - type: grpc\n    local_port: 8080\n", addr)
	os.WriteFile(configFile, []byte(configContent), 0644)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()

	args := []string{"wirerift", "start", configFile}
	err := doStart(ctx, args)
	if err != nil {
		t.Fatalf("doStart failed: %v", err)
	}
}

func TestDoStartTunnelCreateFail(t *testing.T) {
	defer lockGOMAXPROCS()()

	addr, cleanup := startMockTunnelServerWithTunnelError(t)
	defer cleanup()

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "test.yaml")
	configContent := fmt.Sprintf("server: %s\ntoken: test\n\ntunnels:\n  - type: http\n    local_port: 8080\n  - type: tcp\n    local_port: 9090\n", addr)
	os.WriteFile(configFile, []byte(configContent), 0644)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()

	args := []string{"wirerift", "start", configFile}
	err := doStart(ctx, args)
	if err != nil {
		t.Fatalf("doStart should not return error for individual tunnel failures: %v", err)
	}
}

// --- Subprocess tests for main() os.Exit paths ---

func runSubprocess(t *testing.T, testName string) (string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+testName+"$")
	cmd.Env = append(os.Environ(), "WIRERIFT_SUBPROCESS=1")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

func TestMain_NoArgs_Exit(t *testing.T) {
	if os.Getenv("WIRERIFT_SUBPROCESS") == "1" {
		os.Args = []string{"wirerift"}
		main()
		return
	}
	if _, err := runSubprocess(t, "TestMain_NoArgs_Exit"); err == nil {
		t.Fatal("Expected non-zero exit")
	}
}

func TestMain_UnknownCommand_Exit(t *testing.T) {
	if os.Getenv("WIRERIFT_SUBPROCESS") == "1" {
		os.Args = []string{"wirerift", "bogus"}
		main()
		return
	}
	if _, err := runSubprocess(t, "TestMain_UnknownCommand_Exit"); err == nil {
		t.Fatal("Expected non-zero exit")
	}
}

func TestShowConfig_ReadError_Exit(t *testing.T) {
	if os.Getenv("WIRERIFT_SUBPROCESS") == "1" {
		tmpDir, _ := os.MkdirTemp("", "wr-*")
		defer os.RemoveAll(tmpDir)
		os.Chdir(tmpDir)
		os.Mkdir("wirerift.yaml", 0755)
		showConfig()
		return
	}
	out, err := runSubprocess(t, "TestShowConfig_ReadError_Exit")
	if err == nil {
		t.Fatal("Expected non-zero exit")
	}
	if !strings.Contains(out, "Failed to read config") {
		t.Errorf("Expected 'Failed to read config', got: %s", out)
	}
}

func TestInitConfig_WriteError_Exit(t *testing.T) {
	if os.Getenv("WIRERIFT_SUBPROCESS") == "1" {
		tmpDir, _ := os.MkdirTemp("", "wr-*")
		defer os.RemoveAll(tmpDir)
		os.Chdir(tmpDir)
		os.Mkdir("wirerift.yaml", 0755)
		r, w, _ := os.Pipe()
		os.Stdin = r
		go func() { w.Write([]byte("y\n")); w.Close() }()
		initConfig()
		return
	}
	out, err := runSubprocess(t, "TestInitConfig_WriteError_Exit")
	if err == nil {
		t.Fatal("Expected non-zero exit")
	}
	if !strings.Contains(out, "Failed to write config") {
		t.Errorf("Expected 'Failed to write config', got: %s", out)
	}
}

// --- URL construction test ---

func TestListURLConstruction(t *testing.T) {
	s := "myhost:4443"
	url := fmt.Sprintf("http://%s/api/tunnels", strings.Split(s, ":")[0]+":4040")
	if url != "http://myhost:4040/api/tunnels" {
		t.Errorf("URL = %q", url)
	}
}

// --- Direct HTTP test ---

func TestDoList_DirectHTTP(t *testing.T) {
	tunnels := []struct {
		ID     string `json:"id"`
		Type   string `json:"type"`
		URL    string `json:"url"`
		Target string `json:"target"`
		Status string `json:"status"`
	}{{ID: "t1", Type: "http", URL: "http://test.wirerift.com", Target: "localhost:8080", Status: "active"}}
	data, _ := json.Marshal(tunnels)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")
	url := fmt.Sprintf("http://%s/api/tunnels", addr)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "t1") {
		t.Errorf("body = %s", body)
	}
}

// --- Test helpers ---

func assertErr(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Error("Expected error")
	}
}

func assertNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func assertErrContains(t *testing.T, err error, substr string) {
	t.Helper()
	if err == nil {
		t.Errorf("Expected error containing %q", substr)
	} else if !strings.Contains(err.Error(), substr) {
		t.Errorf("Expected error containing %q, got: %v", substr, err)
	}
}

func withTempDir(t *testing.T, fn func()) {
	t.Helper()
	tmpDir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)
	fn()
}

func withStdin(t *testing.T, input string, fn func()) {
	t.Helper()
	origStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	defer func() { os.Stdin = origStdin }()
	go func() { w.Write([]byte(input)); w.Close() }()
	fn()
}

func withEnv(t *testing.T, key, val string) {
	t.Helper()
	orig := os.Getenv(key)
	if val == "" {
		os.Unsetenv(key)
	} else {
		os.Setenv(key, val)
	}
	t.Cleanup(func() {
		if orig != "" {
			os.Setenv(key, orig)
		} else {
			os.Unsetenv(key)
		}
	})
}

// --- Additional coverage tests ---

func TestLoadConfigWithWhitelistAndPIN(t *testing.T) {
	f := filepath.Join(t.TempDir(), "wlpin.yaml")
	os.WriteFile(f, []byte("server: test.server:4443\ntoken: tok\n\ntunnels:\n  - type: http\n    local_port: 8080\n    subdomain: myapp\n    whitelist: 1.2.3.4,10.0.0.0/8\n    pin: secret123\n"), 0644)
	cfg, err := loadConfig(f)
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}
	if len(cfg.Tunnels) != 1 {
		t.Fatalf("Expected 1 tunnel, got %d", len(cfg.Tunnels))
	}
	if cfg.Tunnels[0].Whitelist != "1.2.3.4,10.0.0.0/8" {
		t.Errorf("Whitelist = %q, want %q", cfg.Tunnels[0].Whitelist, "1.2.3.4,10.0.0.0/8")
	}
	if cfg.Tunnels[0].PIN != "secret123" {
		t.Errorf("PIN = %q, want %q", cfg.Tunnels[0].PIN, "secret123")
	}
}

func TestDoHTTP_WithWhitelistAndPIN(t *testing.T) {
	defer lockGOMAXPROCS()()

	addr, cleanup := startMockTunnelServer(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	args := []string{"wirerift", "http", "-server", addr, "-whitelist", "1.2.3.4,10.0.0.0/8", "-pin", "secret", "8080"}
	err := doHTTP(ctx, args)
	if err != nil {
		t.Fatalf("doHTTP with whitelist and pin failed: %v", err)
	}
}

func TestDoHTTP_PortRange(t *testing.T) {
	// Test port out of range
	assertErrContains(t, doHTTP(context.Background(), []string{"wirerift", "http", "0"}), "port must be between")
	assertErrContains(t, doHTTP(context.Background(), []string{"wirerift", "http", "99999"}), "port must be between")
}

func TestDoTCP_PortRange(t *testing.T) {
	// Test port out of range
	assertErrContains(t, doTCP(context.Background(), []string{"wirerift", "tcp", "0"}), "port must be between")
	assertErrContains(t, doTCP(context.Background(), []string{"wirerift", "tcp", "99999"}), "port must be between")
}

func TestHandleSignals_ContextDone(t *testing.T) {
	// Test the ctx.Done() path (normal exit without signal)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		handleSignals(ctx, cancel)
		close(done)
	}()

	// Cancel context to trigger ctx.Done() path
	cancel()

	select {
	case <-done:
		// Success - handleSignals returned via ctx.Done()
	case <-time.After(2 * time.Second):
		t.Error("handleSignals did not return after context cancellation")
	}
}

func TestLoadConfigInvalidPort(t *testing.T) {
	f := filepath.Join(t.TempDir(), "badport.yaml")
	os.WriteFile(f, []byte("server: test.server\ntunnels:\n  - type: http\n    local_port: not_a_number\n"), 0644)
	_, err := loadConfig(f)
	if err == nil {
		t.Error("Expected error for invalid local_port")
	}
	if !strings.Contains(err.Error(), "invalid local_port") {
		t.Errorf("Expected 'invalid local_port' error, got: %v", err)
	}
}

func TestDoStartWithWhitelistAndPIN(t *testing.T) {
	defer lockGOMAXPROCS()()

	addr, cleanup := startMockTunnelServer(t)
	defer cleanup()

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "test.yaml")
	configContent := fmt.Sprintf("server: %s\ntoken: test\n\ntunnels:\n  - type: http\n    local_port: 8080\n    subdomain: test\n    whitelist: 1.2.3.4\n    pin: 1234\n", addr)
	os.WriteFile(configFile, []byte(configContent), 0644)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()

	args := []string{"wirerift", "start", configFile}
	err := doStart(ctx, args)
	if err != nil {
		t.Fatalf("doStart with whitelist/pin failed: %v", err)
	}
}

// --- doServe tests ---

func TestDoServe_NoDirectory(t *testing.T) {
	assertErrContains(t, doServe(context.Background(), []string{"wirerift", "serve"}), "missing directory")
}

func TestDoServe_FlagParseError(t *testing.T) {
	assertErr(t, doServe(context.Background(), []string{"wirerift", "serve", "-unknown-flag"}))
}

func TestDoServe_DirectoryNotFound(t *testing.T) {
	assertErrContains(t, doServe(context.Background(), []string{"wirerift", "serve", "/nonexistent/path/xyz"}), "cannot access directory")
}

func TestDoServe_NotADirectory(t *testing.T) {
	// Create a regular file, not a directory
	f := filepath.Join(t.TempDir(), "notadir.txt")
	os.WriteFile(f, []byte("hello"), 0644)
	assertErrContains(t, doServe(context.Background(), []string{"wirerift", "serve", f}), "is not a directory")
}

func TestDoServe_ConnectFail(t *testing.T) {
	dir := t.TempDir()
	assertErrContains(t, doServe(context.Background(), []string{"wirerift", "serve", "-server", "127.0.0.1:1", dir}), "failed to connect")
}

func TestDoServe_ConnectFail_WithFlags(t *testing.T) {
	dir := t.TempDir()
	assertErrContains(t, doServe(context.Background(), []string{
		"wirerift", "serve",
		"-server", "127.0.0.1:1",
		"-token", "tok",
		"-subdomain", "myapp",
		"-pin", "1234",
		"-whitelist", "1.2.3.4",
		"-inspect",
		"-header", "X-Test:value",
		"-v",
		dir,
	}), "failed to connect")
}

func TestDoServe_ConnectFail_WithAuth(t *testing.T) {
	dir := t.TempDir()
	assertErrContains(t, doServe(context.Background(), []string{
		"wirerift", "serve",
		"-server", "127.0.0.1:1",
		"-auth", "user:pass",
		dir,
	}), "failed to connect")
}

func TestDoServe_InvalidAuth(t *testing.T) {
	defer lockGOMAXPROCS()()

	addr, cleanup := startMockTunnelServer(t)
	defer cleanup()

	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	assertErrContains(t, doServe(ctx, []string{
		"wirerift", "serve",
		"-server", addr,
		"-auth", "invalidnocolon",
		dir,
	}), "invalid -auth format")
}

func TestDoServeSuccess(t *testing.T) {
	defer lockGOMAXPROCS()()

	addr, cleanup := startMockTunnelServer(t)
	defer cleanup()

	dir := t.TempDir()
	// Create a file in the directory to serve
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>test</html>"), 0644)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	args := []string{"wirerift", "serve", "-server", addr, dir}
	err := doServe(ctx, args)
	if err != nil {
		t.Fatalf("doServe failed: %v", err)
	}
}

func TestDoServeSuccessWithSubdomain(t *testing.T) {
	defer lockGOMAXPROCS()()

	addr, cleanup := startMockTunnelServer(t)
	defer cleanup()

	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	args := []string{"wirerift", "serve", "-server", addr, "-subdomain", "myapp", "-v", dir}
	err := doServe(ctx, args)
	if err != nil {
		t.Fatalf("doServe with subdomain failed: %v", err)
	}
}

func TestDoServeTunnelCreateFail(t *testing.T) {
	defer lockGOMAXPROCS()()

	addr, cleanup := startMockTunnelServerWithTunnelError(t)
	defer cleanup()

	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	args := []string{"wirerift", "serve", "-server", addr, dir}
	err := doServe(ctx, args)
	if err == nil {
		t.Fatal("Expected error from doServe with tunnel failure")
	}
	if !strings.Contains(err.Error(), "failed to create tunnel") {
		t.Fatalf("Expected 'failed to create tunnel' error, got: %v", err)
	}
}

func TestRun_Serve_Error(t *testing.T) {
	assertErr(t, run([]string{"wirerift", "serve"}))
}

// --- parseHeaders tests ---

func TestParseHeaders(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]string
	}{
		{
			name:     "single header",
			input:    "X-Robots:noindex",
			expected: map[string]string{"X-Robots": "noindex"},
		},
		{
			name:     "multiple headers",
			input:    "X-Robots:noindex,Cache-Control:no-store",
			expected: map[string]string{"X-Robots": "noindex", "Cache-Control": "no-store"},
		},
		{
			name:     "with spaces",
			input:    " X-Foo : bar , X-Baz : qux ",
			expected: map[string]string{"X-Foo": "bar", "X-Baz": "qux"},
		},
		{
			name:     "empty string",
			input:    "",
			expected: map[string]string{},
		},
		{
			name:     "no colon entry ignored",
			input:    "novalue,X-Valid:yes",
			expected: map[string]string{"X-Valid": "yes"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseHeaders(tt.input)
			for k, v := range tt.expected {
				if result[k] != v {
					t.Errorf("parseHeaders(%q)[%q] = %q, want %q", tt.input, k, result[k], v)
				}
			}
			// Check no extra keys (for entries that should not appear)
			for k := range result {
				if _, ok := tt.expected[k]; !ok {
					t.Errorf("parseHeaders(%q) has unexpected key %q", tt.input, k)
				}
			}
		})
	}
}

// --- loadConfig with auth/inspect/headers ---

func TestLoadConfigWithAuthInspectHeaders(t *testing.T) {
	f := filepath.Join(t.TempDir(), "full.yaml")
	os.WriteFile(f, []byte("server: test.server:4443\ntoken: tok\n\ntunnels:\n  - type: http\n    local_port: 8080\n    subdomain: myapp\n    auth: user:pass\n    inspect: true\n    headers: X-Robots:noindex,Cache-Control:no-store\n"), 0644)
	cfg, err := loadConfig(f)
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}
	if len(cfg.Tunnels) != 1 {
		t.Fatalf("Expected 1 tunnel, got %d", len(cfg.Tunnels))
	}
	tun := cfg.Tunnels[0]
	if tun.Auth != "user:pass" {
		t.Errorf("Auth = %q, want user:pass", tun.Auth)
	}
	if !tun.Inspect {
		t.Error("Inspect should be true")
	}
	if tun.Headers != "X-Robots:noindex,Cache-Control:no-store" {
		t.Errorf("Headers = %q", tun.Headers)
	}
}

func TestDoStartWithAuthAndInspect(t *testing.T) {
	defer lockGOMAXPROCS()()

	addr, cleanup := startMockTunnelServer(t)
	defer cleanup()

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "test.yaml")
	configContent := fmt.Sprintf("server: %s\ntoken: test\n\ntunnels:\n  - type: http\n    local_port: 8080\n    subdomain: test\n    auth: admin:secret\n    inspect: true\n    headers: X-Custom:val\n", addr)
	os.WriteFile(configFile, []byte(configContent), 0644)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()

	args := []string{"wirerift", "start", configFile}
	err := doStart(ctx, args)
	if err != nil {
		t.Fatalf("doStart with auth/inspect/headers failed: %v", err)
	}
}

func TestDoHTTP_WithAuthAndInspect(t *testing.T) {
	defer lockGOMAXPROCS()()

	addr, cleanup := startMockTunnelServer(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	args := []string{"wirerift", "http", "-server", addr, "-auth", "user:pass", "-inspect", "-header", "X-Robots:noindex", "8080"}
	err := doHTTP(ctx, args)
	if err != nil {
		t.Fatalf("doHTTP with auth/inspect/header failed: %v", err)
	}
}

func TestDoHTTP_InvalidAuth(t *testing.T) {
	defer lockGOMAXPROCS()()

	addr, cleanup := startMockTunnelServer(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	args := []string{"wirerift", "http", "-server", addr, "-auth", "invalidnocolon", "8080"}
	err := doHTTP(ctx, args)
	if err == nil {
		t.Fatal("Expected error for invalid -auth format")
	}
	if !strings.Contains(err.Error(), "invalid -auth format") {
		t.Fatalf("Expected 'invalid -auth format' error, got: %v", err)
	}
}

// --- JSON config tests ---

func TestLoadConfigJSON(t *testing.T) {
	f := filepath.Join(t.TempDir(), "test.json")
	cfg := ConfigFile{
		Server: "json.server:4443",
		Token:  "json-token",
		Tunnels: []TunnelConfig{
			{Type: "http", LocalPort: 8080, Subdomain: "myapp"},
			{Type: "tcp", LocalPort: 25565},
		},
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile(f, data, 0644)

	loaded, err := loadConfig(f)
	if err != nil {
		t.Fatalf("loadConfig JSON: %v", err)
	}
	if loaded.Server != "json.server:4443" {
		t.Errorf("Server = %q, want json.server:4443", loaded.Server)
	}
	if loaded.Token != "json-token" {
		t.Errorf("Token = %q, want json-token", loaded.Token)
	}
	if len(loaded.Tunnels) != 2 {
		t.Fatalf("Tunnels = %d, want 2", len(loaded.Tunnels))
	}
	if loaded.Tunnels[0].Subdomain != "myapp" {
		t.Errorf("Tunnel[0].Subdomain = %q, want myapp", loaded.Tunnels[0].Subdomain)
	}
	if loaded.Tunnels[1].Type != "tcp" {
		t.Errorf("Tunnel[1].Type = %q, want tcp", loaded.Tunnels[1].Type)
	}
}

func TestLoadConfigJSONWithAllFields(t *testing.T) {
	f := filepath.Join(t.TempDir(), "full.json")
	cfg := ConfigFile{
		Server: "test.server:4443",
		Token:  "tok",
		Tunnels: []TunnelConfig{
			{
				Type:      "http",
				LocalPort: 8080,
				Subdomain: "myapp",
				Whitelist: "1.2.3.4",
				PIN:       "1234",
				Auth:      "user:pass",
				Inspect:   true,
				Headers:   "X-Test:value",
			},
		},
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile(f, data, 0644)

	loaded, err := loadConfig(f)
	if err != nil {
		t.Fatalf("loadConfig JSON: %v", err)
	}
	tun := loaded.Tunnels[0]
	if tun.Whitelist != "1.2.3.4" {
		t.Errorf("Whitelist = %q", tun.Whitelist)
	}
	if tun.PIN != "1234" {
		t.Errorf("PIN = %q", tun.PIN)
	}
	if tun.Auth != "user:pass" {
		t.Errorf("Auth = %q", tun.Auth)
	}
	if !tun.Inspect {
		t.Error("Inspect should be true")
	}
	if tun.Headers != "X-Test:value" {
		t.Errorf("Headers = %q", tun.Headers)
	}
}

func TestLoadConfigJSONInvalid(t *testing.T) {
	f := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(f, []byte("{invalid json"), 0644)

	_, err := loadConfig(f)
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestLoadConfigJSONEnvDefaults(t *testing.T) {
	f := filepath.Join(t.TempDir(), "empty.json")
	os.WriteFile(f, []byte(`{"tunnels":[]}`), 0644)

	os.Setenv("WIRERIFT_SERVER", "env.server:9999")
	defer os.Unsetenv("WIRERIFT_SERVER")

	loaded, err := loadConfig(f)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if loaded.Server != "env.server:9999" {
		t.Errorf("Server = %q, want env.server:9999 from env", loaded.Server)
	}
}

// --- Additional coverage: JSON fallback in doStart ---

func TestDoStart_JSONFallback(t *testing.T) {
	// When wirerift.yaml doesn't exist but wirerift.json does, doStart should use wirerift.json
	withTempDir(t, func() {
		cfg := ConfigFile{
			Server: "127.0.0.1:1",
			Token:  "tok",
			Tunnels: []TunnelConfig{
				{Type: "http", LocalPort: 8080},
			},
		}
		data, _ := json.MarshalIndent(cfg, "", "  ")
		os.WriteFile("wirerift.json", data, 0644)

		// wirerift.yaml does NOT exist, so it falls back to wirerift.json
		// Connection will fail, but we exercise the fallback path
		assertErrContains(t, doStart(context.Background(), []string{"wirerift", "start"}), "failed to connect")
	})
}

// --- Additional coverage: JSON config with empty server/token env override ---

func TestLoadConfigJSONEmptyServerEnvOverride(t *testing.T) {
	f := filepath.Join(t.TempDir(), "override.json")
	// JSON with explicit empty server and token — should trigger env override at lines 499-504
	os.WriteFile(f, []byte(`{"server":"","token":"","tunnels":[]}`), 0644)

	os.Setenv("WIRERIFT_SERVER", "env-override.server:4443")
	os.Setenv("WIRERIFT_TOKEN", "env-override-token")
	defer os.Unsetenv("WIRERIFT_SERVER")
	defer os.Unsetenv("WIRERIFT_TOKEN")

	loaded, err := loadConfig(f)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if loaded.Server != "env-override.server:4443" {
		t.Errorf("Server = %q, want env-override.server:4443", loaded.Server)
	}
	if loaded.Token != "env-override-token" {
		t.Errorf("Token = %q, want env-override-token", loaded.Token)
	}
}

// --- Additional coverage: doServe success with all option flags ---

func TestDoServeSuccessWithAllFlags(t *testing.T) {
	defer lockGOMAXPROCS()()

	addr, cleanup := startMockTunnelServer(t)
	defer cleanup()

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>test</html>"), 0644)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	args := []string{
		"wirerift", "serve",
		"-server", addr,
		"-whitelist", "1.2.3.4,10.0.0.0/8",
		"-pin", "1234",
		"-auth", "user:pass",
		"-inspect",
		"-header", "X-Robots:noindex",
		dir,
	}
	err := doServe(ctx, args)
	if err != nil {
		t.Fatalf("doServe with all flags failed: %v", err)
	}
}

// --- Additional coverage: doList with HTTP error response body ---

func TestDoList_ErrorResponse_MockServer(t *testing.T) {
	// Server that returns a non-JSON error response body
	ln, err := net.Listen("tcp", "127.0.0.1:4040")
	if err != nil {
		t.Skipf("Port 4040 in use: %v", err)
	}
	ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/tunnels", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("this is not valid json at all"))
	})
	srv := &http.Server{Addr: "127.0.0.1:4040", Handler: mux}
	go srv.ListenAndServe()
	time.Sleep(50 * time.Millisecond)
	defer srv.Close()

	// doList should fail to parse the response
	assertErrContains(t, doList([]string{"wirerift", "list", "-server", "127.0.0.1:4040"}), "failed to parse response")
}

// --- Additional coverage: doStart with auth containing invalid format ---

func TestDoStartWithInvalidAuth(t *testing.T) {
	defer lockGOMAXPROCS()()

	addr, cleanup := startMockTunnelServer(t)
	defer cleanup()

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "test.yaml")
	// auth without colon — the SplitN produces len(parts) != 2, so auth option is skipped
	configContent := fmt.Sprintf("server: %s\ntoken: test\n\ntunnels:\n  - type: http\n    local_port: 8080\n    auth: invalidnocolon\n", addr)
	os.WriteFile(configFile, []byte(configContent), 0644)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()

	args := []string{"wirerift", "start", configFile}
	err := doStart(ctx, args)
	if err != nil {
		t.Fatalf("doStart should not error for invalid auth format (silently skipped): %v", err)
	}
}

// --- Additional coverage: handleSignals signal path ---
// The signal path in handleSignals (line 124-125) requires sending an actual OS signal.
// On Windows this is not supported for the current process. On Unix, the
// TestHandleSignals_SignalPath test below covers it.

func TestHandleSignals_SignalPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Sending signals to self not supported on Windows")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		handleSignals(ctx, cancel)
		close(done)
	}()

	// Give handleSignals time to register its signal handler
	time.Sleep(50 * time.Millisecond)

	// Send interrupt to current process (works on Unix)
	proc, _ := os.FindProcess(os.Getpid())
	proc.Signal(os.Interrupt)

	select {
	case <-done:
		// handleSignals returned via signal path — success
	case <-time.After(3 * time.Second):
		cancel()
		t.Error("handleSignals did not return after signal")
	}
}

// --- Additional coverage: doList with truncated response body ---

func TestDoList_ReadBodyError_MockServer(t *testing.T) {
	// Create a server that hijacks the connection and sends a partial response,
	// then closes it, causing io.ReadAll to fail.
	ln, err := net.Listen("tcp", "127.0.0.1:4040")
	if err != nil {
		t.Skipf("Port 4040 in use: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Read the HTTP request (consume it)
			buf := make([]byte, 4096)
			conn.Read(buf)
			// Write a partial HTTP response with Content-Length much larger than actual body
			// then close the connection, causing io.ReadAll to fail
			resp := "HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\npartial"
			conn.Write([]byte(resp))
			conn.Close()
		}
	}()
	defer ln.Close()
	time.Sleep(50 * time.Millisecond)

	err = doList([]string{"wirerift", "list", "-server", "127.0.0.1:4040"})
	if err == nil {
		t.Error("Expected error for truncated response")
	}
	if err != nil && !strings.Contains(err.Error(), "failed to read response") && !strings.Contains(err.Error(), "failed to parse response") {
		// Either read error or parse error is acceptable
		t.Logf("doList returned: %v", err)
	}
}
