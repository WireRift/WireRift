package mux

import (
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// waitWritersParked blocks until n goroutines are parked in a select inside
// Stream.Write (gated on the runtime, not on sleeps of a fixed length).
func waitWritersParked(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		buf := make([]byte, 1<<20)
		buf = buf[:runtime.Stack(buf, true)]
		parked := 0
		for _, g := range strings.Split(string(buf), "\n\n") {
			if strings.Contains(g, "mux.(*Stream).Write") && strings.Contains(g, "[select") {
				parked++
			}
		}
		if parked >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("%d writers never parked", n)
}

// A Write waiting for send credit must fail once the stream is closed for
// writing; Close used to leave it parked until a window update or mux death.
func TestCloseWakesWritersParkedOnWindow(t *testing.T) {
	for _, writers := range []int{1, 2} { // the wake token must be passed on
		local, _ := halfClosePair(t, 0) // peer never reads: no window updates
		done := make(chan error, writers)
		for i := 0; i < writers; i++ {
			go func() {
				_, err := local.Write(make([]byte, 2*int(local.maxWindow)))
				done <- err
			}()
		}
		waitWritersParked(t, writers)
		local.Close()
		for i := 0; i < writers; i++ {
			select {
			case err := <-done:
				if err != ErrStreamClosed {
					t.Fatalf("writers=%d: Write = %v, want ErrStreamClosed", writers, err)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("writers=%d: Write still blocked after Close", writers)
			}
		}
	}
}

// io.Reader: an empty read returns at once instead of waiting for data.
func TestReadEmptyBufferDoesNotBlock(t *testing.T) {
	_, remote := halfClosePair(t, 0)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if n, err := remote.Read(nil); n != 0 || err != nil {
			t.Errorf("Read(nil) = %d, %v; want 0, nil", n, err)
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Read of an empty buffer blocked")
	}
}

// The stream limit must hold when many callers open streams at once.
func TestOpenStreamLimitHoldsUnderConcurrency(t *testing.T) {
	const limit, workers = 3, 64
	for round := 0; round < 200; round++ {
		a, b := net.Pipe()
		cfg := DefaultConfig()
		cfg.MaxStreams = limit
		m := New(a, cfg)
		gate := make(chan struct{})
		var wg sync.WaitGroup
		var mu sync.Mutex
		opened := 0
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-gate
				if _, err := m.OpenStream(); err == nil {
					mu.Lock()
					opened++
					mu.Unlock()
				}
			}()
		}
		close(gate)
		wg.Wait()
		a.Close()
		b.Close()
		if opened != limit {
			t.Fatalf("round %d: opened %d streams, limit %d", round, opened, limit)
		}
	}
}
