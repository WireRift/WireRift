package integration

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A stream may run far longer than the idle timeout as long as data keeps
// flowing. (The server used to enforce an absolute 60s WriteTimeout, cutting
// every SSE stream and long download at one minute.)
func TestStreamLongerThanIdleTimeoutIsNotCut(t *testing.T) {
	const events = 25
	edge, host := startTunnelIdle(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 0; i < events; i++ {
			fmt.Fprintf(w, "data: %d\n\n", i)
			w.(http.Flusher).Flush()
			time.Sleep(120 * time.Millisecond)
		}
	}), "long", 400*time.Millisecond) // total ~3s, i.e. 7x the idle timeout

	req, _ := http.NewRequest("GET", "http://"+edge+"/", nil)
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got := 0
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "data:") {
			got++
		}
	}
	if got != events || sc.Err() != nil {
		t.Errorf("received %d/%d events (err=%v): the stream was cut", got, events, sc.Err())
	}
}

// A visitor that stops reading must not pin the server forever.
func TestStalledVisitorIsDropped(t *testing.T) {
	ended := make(chan time.Duration, 1)
	edge, host := startTunnelIdle(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		chunk := make([]byte, 64<<10)
		for {
			if _, err := w.Write(chunk); err != nil {
				ended <- time.Since(start)
				return
			}
		}
	}), "stall", 300*time.Millisecond)

	conn, err := net.Dial("tcp", edge)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", host)
	buf := make([]byte, 1024)
	if _, err := conn.Read(buf); err != nil { // read a little, then stop reading
		t.Fatal(err)
	}

	select {
	case d := <-ended:
		t.Logf("server dropped the stalled visitor after %v", d)
	case <-time.After(15 * time.Second):
		t.Fatal("a visitor that stopped reading pinned the response forever")
	}
}

// Uploads: progress keeps them alive, a stall ends them.
func TestSlowUploadSurvivesButStalledUploadDoesNot(t *testing.T) {
	edge, host := startTunnelIdle(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		fmt.Fprintf(w, "got %d", n)
	}), "up", 400*time.Millisecond)

	post := func(pause time.Duration, parts int) (string, error) {
		conn, err := net.Dial("tcp", edge)
		if err != nil {
			return "", err
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(15 * time.Second))
		fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", host, parts*5)
		for i := 0; i < parts; i++ {
			if _, err := conn.Write([]byte("hello")); err != nil {
				return "", err
			}
			time.Sleep(pause)
		}
		b, err := io.ReadAll(conn)
		return string(b), err
	}

	// 8 pieces 150ms apart: ~1.2s total, 3x the idle timeout, but always progressing.
	if out, err := post(150*time.Millisecond, 8); err != nil || !strings.Contains(out, "got 40") {
		t.Errorf("slow but steady upload failed: %q %v", out, err)
	}
	// One piece, then silence for longer than the idle timeout.
	out, _ := post(1500*time.Millisecond, 2)
	if strings.Contains(out, "got 10") {
		t.Errorf("a stalled upload was accepted: %q", out)
	}
}
