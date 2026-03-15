package server

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// WebhookRelay fans out incoming requests to multiple local endpoints.
type WebhookRelay struct {
	tunnelID  string
	endpoints []string // local addresses to forward to
	mu        sync.RWMutex
}

// WebhookResult holds the result of forwarding to one endpoint.
type WebhookResult struct {
	Endpoint   string `json:"endpoint"`
	StatusCode int    `json:"status_code"`
	Duration   string `json:"duration"`
	Error      string `json:"error,omitempty"`
}

// NewWebhookRelay creates a relay that fans out to multiple endpoints.
func NewWebhookRelay(tunnelID string, endpoints []string) *WebhookRelay {
	return &WebhookRelay{
		tunnelID:  tunnelID,
		endpoints: endpoints,
	}
}

// Relay forwards a request to all configured endpoints concurrently.
// Returns results from each endpoint.
func (wr *WebhookRelay) Relay(method, path string, headers http.Header, body []byte) []WebhookResult {
	wr.mu.RLock()
	endpoints := make([]string, len(wr.endpoints))
	copy(endpoints, wr.endpoints)
	wr.mu.RUnlock()

	results := make([]WebhookResult, len(endpoints))
	var wg sync.WaitGroup

	client := &http.Client{Timeout: 10 * time.Second}

	for i, ep := range endpoints {
		wg.Add(1)
		go func(idx int, endpoint string) {
			defer wg.Done()

			url := fmt.Sprintf("http://%s%s", endpoint, path)
			req, err := http.NewRequest(method, url, bytes.NewReader(body))
			if err != nil {
				results[idx] = WebhookResult{Endpoint: endpoint, Error: err.Error()}
				return
			}

			// Copy headers
			for k, vs := range headers {
				for _, v := range vs {
					req.Header.Add(k, v)
				}
			}

			start := time.Now()
			resp, err := client.Do(req)
			dur := time.Since(start)

			if err != nil {
				results[idx] = WebhookResult{
					Endpoint: endpoint,
					Duration: dur.String(),
					Error:    err.Error(),
				}
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			results[idx] = WebhookResult{
				Endpoint:   endpoint,
				StatusCode: resp.StatusCode,
				Duration:   dur.String(),
			}
		}(i, ep)
	}

	wg.Wait()
	return results
}

// AddEndpoint adds a new endpoint to the relay.
func (wr *WebhookRelay) AddEndpoint(endpoint string) {
	wr.mu.Lock()
	defer wr.mu.Unlock()
	wr.endpoints = append(wr.endpoints, endpoint)
}

// RemoveEndpoint removes an endpoint from the relay.
func (wr *WebhookRelay) RemoveEndpoint(endpoint string) {
	wr.mu.Lock()
	defer wr.mu.Unlock()
	for i, ep := range wr.endpoints {
		if ep == endpoint {
			wr.endpoints = append(wr.endpoints[:i], wr.endpoints[i+1:]...)
			return
		}
	}
}

// Endpoints returns current endpoints.
func (wr *WebhookRelay) Endpoints() []string {
	wr.mu.RLock()
	defer wr.mu.RUnlock()
	result := make([]string, len(wr.endpoints))
	copy(result, wr.endpoints)
	return result
}
