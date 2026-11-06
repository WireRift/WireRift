package server

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestServerRejectsSecondStart(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ControlAddr = "127.0.0.1:0"
	cfg.HTTPAddr = "127.0.0.1:0"
	s := New(cfg, nil)
	if err := s.Start(); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	firstControl := s.controlListener
	firstHTTP := s.httpListener

	err := s.Start()
	if err == nil {
		// Pre-fix cleanup: the second Start overwrote the listener fields, so
		// close both generations explicitly to avoid leaking proof goroutines.
		s.cancel()
		_ = firstControl.Close()
		_ = firstHTTP.Close()
		_ = s.controlListener.Close()
		_ = s.httpListener.Close()
		wait := make(chan struct{})
		go func() { s.wg.Wait(); close(wait) }()
		select {
		case <-wait:
		case <-time.After(2 * time.Second):
			t.Fatal("second Start was accepted and leaked server goroutines")
		}
		t.Fatal("second Start was accepted")
	}
	if !strings.Contains(err.Error(), "already") {
		t.Fatalf("second Start error = %v, want lifecycle rejection", err)
	}
	if err := s.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestConcurrentStopIsIdempotent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ControlAddr = "127.0.0.1:0"
	cfg.HTTPAddr = "127.0.0.1:0"
	s := New(cfg, nil)
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	const callers = 8
	start := make(chan struct{})
	errors := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errors <- s.Stop()
		}()
	}
	close(start)
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent Stop: %v", err)
		}
	}
}

func TestServerRejectsStartAfterStop(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ControlAddr = "127.0.0.1:0"
	cfg.HTTPAddr = "127.0.0.1:0"
	s := New(cfg, nil)
	if err := s.Stop(); err != nil {
		t.Fatalf("Stop before Start: %v", err)
	}
	if err := s.Start(); err == nil {
		_ = s.Stop()
		t.Fatal("Start succeeded after Stop cancelled the server context")
	}
}

func TestUnexpectedHTTPListenerFailureClearsReadiness(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ControlAddr = "127.0.0.1:0"
	cfg.HTTPAddr = "127.0.0.1:0"
	s := New(cfg, nil)
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop()
	if !s.ready.Load() {
		t.Fatal("server never became ready")
	}
	if err := s.httpListener.Close(); err != nil {
		t.Fatalf("close HTTP listener: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for s.ready.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if s.ready.Load() {
		t.Fatal("server stayed ready after its HTTP edge listener failed")
	}
	select {
	case err := <-s.Errors():
		if !strings.Contains(err.Error(), "HTTP listener failed") {
			t.Fatalf("fatal error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("HTTP listener failure was not reported to the supervisor")
	}
	select {
	case <-s.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("HTTP listener failure did not cancel server work")
	}
}

func TestUnexpectedControlListenerFailureClearsReadiness(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ControlAddr = "127.0.0.1:0"
	cfg.HTTPAddr = "127.0.0.1:0"
	s := New(cfg, nil)
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop()
	if err := s.controlListener.Close(); err != nil {
		t.Fatalf("close control listener: %v", err)
	}
	select {
	case err := <-s.Errors():
		if !strings.Contains(err.Error(), "control listener failed") {
			t.Fatalf("fatal error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("control listener failure was not reported")
	}
	if s.ready.Load() {
		t.Fatal("server stayed ready after its control listener failed")
	}
}
