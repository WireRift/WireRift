package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestWebhookRelayFanOut(t *testing.T) {
	var count1, count2 atomic.Int32

	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count1.Add(1)
		w.WriteHeader(200)
	}))
	defer srv1.Close()

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count2.Add(1)
		w.WriteHeader(201)
	}))
	defer srv2.Close()

	relay := NewWebhookRelay("tun-1", []string{
		srv1.Listener.Addr().String(),
		srv2.Listener.Addr().String(),
	})

	results := relay.Relay("POST", "/webhook", http.Header{
		"Content-Type": []string{"application/json"},
	}, []byte(`{"event":"push"}`))

	if len(results) != 2 {
		t.Fatalf("Expected 2 results, got %d", len(results))
	}

	if results[0].StatusCode != 200 {
		t.Errorf("Endpoint 1: status=%d, want 200", results[0].StatusCode)
	}
	if results[1].StatusCode != 201 {
		t.Errorf("Endpoint 2: status=%d, want 201", results[1].StatusCode)
	}
	if count1.Load() != 1 || count2.Load() != 1 {
		t.Errorf("Both endpoints should receive exactly 1 request")
	}
}

func TestWebhookRelayHeaders(t *testing.T) {
	var receivedContentType string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		w.Write(body)
	}))
	defer srv.Close()

	relay := NewWebhookRelay("tun-1", []string{srv.Listener.Addr().String()})
	relay.Relay("POST", "/hook", http.Header{
		"Content-Type":    []string{"application/json"},
		"X-GitHub-Event":  []string{"push"},
	}, []byte(`{"ref":"main"}`))

	if receivedContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", receivedContentType)
	}
}

func TestWebhookRelayEndpointError(t *testing.T) {
	relay := NewWebhookRelay("tun-1", []string{"127.0.0.1:1"}) // unreachable
	results := relay.Relay("POST", "/", nil, nil)

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}
	if results[0].Error == "" {
		t.Error("Expected error for unreachable endpoint")
	}
}

func TestWebhookRelayAddRemoveEndpoint(t *testing.T) {
	relay := NewWebhookRelay("tun-1", []string{"localhost:8080"})

	relay.AddEndpoint("localhost:8081")
	eps := relay.Endpoints()
	if len(eps) != 2 {
		t.Errorf("Expected 2 endpoints, got %d", len(eps))
	}

	relay.RemoveEndpoint("localhost:8080")
	eps = relay.Endpoints()
	if len(eps) != 1 {
		t.Errorf("Expected 1 endpoint, got %d", len(eps))
	}
	if eps[0] != "localhost:8081" {
		t.Errorf("Remaining endpoint = %q, want localhost:8081", eps[0])
	}
}

func TestWebhookRelayEmptyEndpoints(t *testing.T) {
	relay := NewWebhookRelay("tun-1", nil)
	results := relay.Relay("GET", "/", nil, nil)
	if len(results) != 0 {
		t.Errorf("Expected 0 results for empty relay, got %d", len(results))
	}
}
