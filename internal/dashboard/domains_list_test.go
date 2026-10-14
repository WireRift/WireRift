package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wirerift/wirerift/internal/auth"
	"github.com/wirerift/wirerift/internal/config"
	"github.com/wirerift/wirerift/internal/server"
)

// TestHandleDomainsListsAllRegisteredDomains verifies that GET /api/domains
// returns every registered domain, including ones registered with an
// account_id. The listing filters by exact account (ListDomains), so the
// handler must not treat the empty account as a wildcard.
func TestHandleDomainsListsAllRegisteredDomains(t *testing.T) {
	authMgr := auth.NewManager()
	srv := server.New(server.DefaultConfig(), nil)
	dm := config.NewDomainManager("wirerift.test")

	d := New(Config{
		Server:      srv,
		AuthManager: authMgr,
		DomainMgr:   dm,
	})
	handler := d.Handler()
	authHeader := "Bearer " + authMgr.DevToken()

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/domains", strings.NewReader(body))
		req.Header.Set("Authorization", authHeader)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	if rec := post(`{"domain":"acct.example.com","account_id":"acct_42"}`); rec.Code != http.StatusOK {
		t.Fatalf("POST domain with account_id = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if rec := post(`{"domain":"plain.example.com"}`); rec.Code != http.StatusOK {
		t.Fatalf("POST domain without account_id = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	req := httptest.NewRequest("GET", "/api/domains", nil)
	req.Header.Set("Authorization", authHeader)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/domains = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var listed []config.CustomDomain
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode listing: %v; body=%s", err, rec.Body.String())
	}

	if len(listed) != 2 {
		t.Errorf("listing has %d domains, want 2: %v", len(listed), listed)
	}
	got := map[string]bool{}
	for _, item := range listed {
		got[item.Domain] = true
	}
	if !got["plain.example.com"] {
		t.Errorf("domain without account_id missing from listing: %v", got)
	}
	if !got["acct.example.com"] {
		t.Errorf("domain registered with account_id acct_42 missing from listing: %v", got)
	}
}
