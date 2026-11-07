package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestUIListenerAcceptsOnlyLoopback(t *testing.T) {
	for _, bad := range []string{"0.0.0.0:0", "192.168.1.5:4041", ":4041", "example.com:80", "nonsense"} {
		if ln, err := uiListener(bad); err == nil {
			ln.Close()
			t.Errorf("-listen %q accepted", bad)
		}
	}
	for _, ok := range []string{"127.0.0.1:0", "localhost:0", "[::1]:0"} {
		ln, err := uiListener(ok)
		if err != nil {
			if ok == "[::1]:0" {
				continue // no IPv6 loopback on this machine
			}
			t.Errorf("-listen %q: %v", ok, err)
			continue
		}
		ln.Close()
	}
}

func TestUIListenerSkipsBusyDefaultPorts(t *testing.T) {
	first, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(defaultUIPort))
	if err != nil {
		t.Skip("the default port is taken on this machine")
	}
	defer first.Close()
	ln, err := uiListener("")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if port := ln.Addr().(*net.TCPAddr).Port; port <= defaultUIPort || port >= defaultUIPort+10 {
		t.Errorf("fell back to port %d", port)
	}
}

func TestBrowserCommand(t *testing.T) {
	for goos, want := range map[string]string{"darwin": "open", "windows": "rundll32", "linux": "xdg-open", "freebsd": "xdg-open"} {
		cmd := browserCommand(goos, "http://127.0.0.1:1/")
		if !strings.HasSuffix(cmd.Args[0], want) || cmd.Args[len(cmd.Args)-1] != "http://127.0.0.1:1/" {
			t.Errorf("%s: %v", goos, cmd.Args)
		}
	}
}

// doUI serves the interface on the address it prints and stops with its context.
func TestDoUIServesAndStops(t *testing.T) {
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- doUI(ctx, []string{"wirerift", "ui", "-listen", "127.0.0.1:0", "-no-open", "-no-save"})
	}()

	line := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(r)
		if sc.Scan() {
			line <- sc.Text()
		}
		io.Copy(io.Discard, r)
	}()
	var first string
	select {
	case first = <-line:
	case <-time.After(5 * time.Second):
		t.Fatal("no address printed")
	}
	url := strings.TrimPrefix(first, "WireRift client interface: ")
	if !strings.HasPrefix(url, "http://127.0.0.1:") || !strings.Contains(url, "/?k=") {
		t.Fatalf("printed %q", first)
	}
	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := hc.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || len(resp.Cookies()) != 1 {
		t.Errorf("opening the printed address: %d, %d cookies", resp.StatusCode, len(resp.Cookies()))
	}
	plain, err := hc.Get(strings.SplitN(url, "/?k=", 2)[0] + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	plain.Body.Close()
	if plain.StatusCode != http.StatusUnauthorized {
		t.Errorf("the API without the key: %d", plain.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("doUI: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("doUI did not stop")
	}
}

func TestDoUIRefusesBadArguments(t *testing.T) {
	if err := doUI(context.Background(), []string{"wirerift", "ui", "-listen", "0.0.0.0:0"}); err == nil {
		t.Error("a non-loopback address must be refused")
	}
	if err := doUI(context.Background(), []string{"wirerift", "ui", "-bogus"}); err == nil {
		t.Error("an unknown flag must be refused")
	}
}
