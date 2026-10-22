package mux

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/proto"
)

// The ID counter running past the 24-bit space must wrap, not end the session.
func TestOpenStreamWrapsAroundIDSpace(t *testing.T) {
	client, _ := newTestPipe(t)
	defer client.Close()

	client.nextID = maxLocalStreamID
	a, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	b, err := client.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream after the last ID: %v (session would be dead)", err)
	}
	if a.ID() != maxLocalStreamID || b.ID() != 2 {
		t.Errorf("IDs = %d, %d; want %d then 2", a.ID(), b.ID(), maxLocalStreamID)
	}
	if b.ID()%2 != 0 || a.ID() > proto.MaxStreamID {
		t.Errorf("IDs must stay even and fit 3 bytes: %d, %d", a.ID(), b.ID())
	}
}

// Wrapping must never hand out an ID that a live stream still owns.
func TestOpenStreamWrapSkipsLiveIDs(t *testing.T) {
	client, _ := newTestPipe(t)
	defer client.Close()

	live2, _ := client.OpenStream() // ID 2
	live4, _ := client.OpenStream() // ID 4
	client.nextID = maxLocalStreamID
	if _, err := client.OpenStream(); err != nil {
		t.Fatal(err)
	}
	got, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	if got.ID() == live2.ID() || got.ID() == live4.ID() || got.ID() != 6 {
		t.Errorf("got ID %d, want 6 (2 and 4 are live)", got.ID())
	}
}

// With every ID in use the allocator must give up instead of looping.
func TestOpenStreamAllIDsLive(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxStreams = 3
	c1, c2 := net.Pipe()
	client := New(c1, cfg)
	defer client.Close()
	defer c2.Close()

	for i := 0; i < 3; i++ {
		if _, err := client.OpenStream(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := client.OpenStream(); err != ErrTooManyStreams {
		t.Errorf("err = %v, want ErrTooManyStreams", err)
	}
}

// End to end: a stream ID that has been fully closed on both sides is reused by
// the next open after the counter wraps, and carries data correctly.
func TestStreamIDReuseAfterWrapCarriesData(t *testing.T) {
	client, server := newTestPipe(t)
	go client.Run()
	go server.Run()

	openAccept := func() (out, in *Stream) {
		t.Helper()
		out, err := client.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		f, _ := proto.EncodeJSONPayload(proto.FrameStreamOpen, out.ID(), &proto.StreamOpen{Protocol: "tcp"})
		if err := client.GetFrameWriter().Write(f); err != nil {
			t.Fatal(err)
		}
		in, err = server.AcceptStream()
		if err != nil {
			t.Fatal(err)
		}
		return out, in
	}

	first, firstIn := openAccept()
	if first.ID() != 2 {
		t.Fatalf("first ID = %d, want 2", first.ID())
	}
	if _, err := first.Write([]byte("one")); err != nil {
		t.Fatal(err)
	}
	first.Close()
	if _, err := io.ReadAll(firstIn); err != nil {
		t.Fatal(err)
	}
	firstIn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for (client.streamCount.Load() != 0 || server.streamCount.Load() != 0) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if client.streamCount.Load() != 0 || server.streamCount.Load() != 0 {
		t.Fatalf("stream 2 not released on both sides: client=%d server=%d", client.streamCount.Load(), server.streamCount.Load())
	}

	client.idMu.Lock()
	client.nextID = maxLocalStreamID
	client.idMu.Unlock()
	wrapped, wrappedIn := openAccept() // takes the last ID
	again, againIn := openAccept()     // wraps to 2
	if again.ID() != 2 {
		t.Fatalf("after the wrap ID = %d, want the reused 2", again.ID())
	}
	_ = wrapped
	_ = wrappedIn

	if _, err := again.Write([]byte("two")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 3)
	if _, err := io.ReadFull(againIn, buf); err != nil || string(buf) != "two" {
		t.Fatalf("data on the reused ID = %q, %v; want \"two\"", buf, err)
	}
}

// Thousands of short streams across the wrap point, from concurrent workers:
// every one must get a usable ID and its own data back.
func TestStreamIDWrapUnderConcurrentLoad(t *testing.T) {
	client, server := newTestPipe(t)
	go client.Run()
	go server.Run()

	client.idMu.Lock()
	client.nextID = maxLocalStreamID - 2*500 // wrap after ~500 opens
	client.idMu.Unlock()

	// Echo server side.
	go func() {
		for {
			in, err := server.AcceptStream()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(in, in)
				in.Close()
			}()
		}
	}()

	const workers, perWorker = 8, 250
	errs := make(chan error, workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			for i := 0; i < perWorker; i++ {
				out, err := client.OpenStream()
				if err != nil {
					errs <- err
					return
				}
				f, _ := proto.EncodeJSONPayload(proto.FrameStreamOpen, out.ID(), &proto.StreamOpen{Protocol: "tcp"})
				if err := client.GetFrameWriter().Write(f); err != nil {
					errs <- err
					return
				}
				msg := []byte{byte(w), byte(i), byte(i >> 8)}
				if _, err := out.Write(msg); err != nil {
					errs <- err
					return
				}
				got := make([]byte, len(msg))
				if _, err := io.ReadFull(out, got); err != nil || string(got) != string(msg) {
					errs <- io.ErrUnexpectedEOF
					return
				}
				out.Close()
				io.Copy(io.Discard, out)
			}
			errs <- nil
		}(w)
	}
	for w := 0; w < workers; w++ {
		select {
		case err := <-errs:
			if err != nil {
				t.Fatalf("worker failed across the ID wrap: %v", err)
			}
		case <-time.After(60 * time.Second):
			t.Fatal("timed out across the ID wrap")
		}
	}
	client.idMu.Lock()
	next := client.nextID
	client.idMu.Unlock()
	if next > maxLocalStreamID/2 { // 2000 opens vs 500 IDs of headroom: must have wrapped
		t.Errorf("nextID = %d: the counter never wrapped", next)
	}
}
