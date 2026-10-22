package mux

import (
	"io"
	"sync"
	"testing"
	"time"

	"github.com/wirerift/wirerift/internal/proto"
)

// After a transfer is fully read, the sender's window must be back at its
// initial size: credit must neither leak (window updates clamped away because
// the debit lagged the send) nor be overdrawn by concurrent writers.
func TestStreamWindowReturnsToInitialAfterTransfer(t *testing.T) {
	client, server := newTestPipe(t)
	go client.Run()
	go server.Run()

	out, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	openFrame, _ := proto.EncodeJSONPayload(proto.FrameStreamOpen, out.ID(), &proto.StreamOpen{Protocol: "tcp"})
	if err := client.GetFrameWriter().Write(openFrame); err != nil {
		t.Fatal(err)
	}
	in, err := server.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}

	const writers, perWriter = 2, 8 << 20
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 32*1024)
			for sent := 0; sent < perWriter; sent += len(buf) {
				if _, err := out.Write(buf); err != nil {
					t.Errorf("write: %v", err)
					return
				}
			}
		}()
	}

	if _, err := io.CopyN(io.Discard, in, writers*perWriter); err != nil {
		t.Fatalf("read: %v", err)
	}
	wg.Wait()

	deadline := time.Now().Add(2 * time.Second)
	for out.window.Load() != out.maxWindow && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := out.window.Load(); got != out.maxWindow {
		t.Fatalf("send window = %d after transfer, want %d", got, out.maxWindow)
	}
}
