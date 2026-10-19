package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Custom domains let a tunnel be served on a name the user owns
// (app.example.com) instead of <sub>.<base domain>.
//
// Ownership is proven statelessly through DNS: the server derives a code
// HMAC(secret, account|domain) and expects it in the TXT record
// "_wirerift.<domain>". Only the owner of the domain's DNS can publish it, and
// only this server (and account) can compute it, so no registration step or
// shared state is needed and the proof survives restarts when the secret is
// persisted.

// customKeyPrefix namespaces custom-domain keys in Server.tunnels. A colon can
// never appear in a valid subdomain, so keys cannot collide with subdomains.
const customKeyPrefix = "domain:"

// isAliasKey reports whether a Server.tunnels key is a custom-domain alias:
// the same *Tunnel is stored under its subdomain and under "domain:<name>", and
// anything that enumerates tunnels must count it once.
func isAliasKey(key any) bool {
	k, ok := key.(string)
	return ok && strings.HasPrefix(k, customKeyPrefix)
}

// TXTResolver looks up TXT records (replaceable in tests).
type TXTResolver func(ctx context.Context, name string) ([]string, error)

// ErrCustomDomain is the parent of every custom-domain validation error.
var ErrCustomDomain = errors.New("invalid custom domain")

// NewDomainSecret returns a fresh random secret for domain proofs.
func NewDomainSecret() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand.Read failed: " + err.Error())
	}
	return b
}

// normalizeCustomDomain validates and lowercases a custom domain. It must be a
// plain multi-label host name outside the server's own base domain.
func normalizeCustomDomain(domain, baseDomain string) (string, error) {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	switch {
	case d == "" || len(d) > 253:
		return "", fmt.Errorf("%w: empty or too long", ErrCustomDomain)
	case net.ParseIP(d) != nil:
		return "", fmt.Errorf("%w: IP addresses are not allowed", ErrCustomDomain)
	case strings.Contains(d, "*"):
		return "", fmt.Errorf("%w: wildcards are not supported", ErrCustomDomain)
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("%w: %q needs at least two labels", ErrCustomDomain, d)
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", fmt.Errorf("%w: %q is not a valid host name", ErrCustomDomain, d)
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("%w: %q is not a valid host name (ASCII letters, digits and hyphens only)", ErrCustomDomain, d)
			}
		}
	}
	if base := strings.ToLower(baseDomain); base != "" && (d == base || strings.HasSuffix(d, "."+base)) {
		return "", fmt.Errorf("%w: %q is under this server's own domain; use a subdomain instead", ErrCustomDomain, d)
	}
	return d, nil
}

// domainProof is the code the owner must publish for (account, domain).
func (s *Server) domainProof(accountID, domain string) string {
	mac := hmac.New(sha256.New, s.domainSecret)
	mac.Write([]byte("wirerift-domain-v1|" + accountID + "|" + domain))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

// txtRecord returns the TXT record name and value that prove ownership.
func (s *Server) txtRecord(accountID, domain string) (name, value string) {
	return "_wirerift." + domain, "wirerift-verification=" + s.domainProof(accountID, domain)
}

// verifyCustomDomain checks the DNS proof. The error tells the user exactly
// which record to create.
func (s *Server) verifyCustomDomain(ctx context.Context, accountID, domain string) error {
	name, want := s.txtRecord(accountID, domain)
	lookup := s.config.TXTResolver
	if lookup == nil {
		lookup = net.DefaultResolver.LookupTXT
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	records, err := lookup(ctx, name)
	for _, rec := range records {
		if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(rec)), []byte(want)) == 1 {
			return nil
		}
	}
	reason := "no matching TXT record found"
	var dnsErr *net.DNSError
	if err != nil && !(errors.As(err, &dnsErr) && dnsErr.IsNotFound) {
		// A real resolver problem (timeout, SERVFAIL, ...), not just a missing record.
		reason = "the TXT lookup failed"
	}
	return fmt.Errorf("custom domain not verified (%s): add a DNS TXT record %s with the value %s, "+
		"and point %s at this server (CNAME to %s); DNS changes can take a few minutes, then try again",
		reason, name, want, domain, s.config.Domain)
}

// normalizeHost lowercases a Host header value and strips the port and any
// trailing dot.
func normalizeHostHeader(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// getTunnelByCustomHost finds the tunnel bound to a custom domain host.
func (s *Server) getTunnelByCustomHost(host string) (*Tunnel, bool) {
	if v, ok := s.tunnels.Load(customKeyPrefix + normalizeHostHeader(host)); ok {
		return v.(*Tunnel), true
	}
	return nil, false
}

// IsCustomDomainActive reports whether host is a custom domain currently bound
// to a live tunnel. The TLS layer uses it to decide whether it may obtain a
// certificate for a name outside the base domain, so certificates are only ever
// requested for domains a verified, connected client is serving.
func (s *Server) IsCustomDomainActive(host string) bool {
	_, ok := s.getTunnelByCustomHost(host)
	return ok
}

// IsHostServed reports whether host currently has a live tunnel behind it: a
// subdomain of the base domain with a registered tunnel, or a bound custom
// domain. The TLS layer uses it so certificates (and ACME orders) are only
// created for names that are actually served.
func (s *Server) IsHostServed(host string) bool {
	host = normalizeHostHeader(host)
	if sub := extractSubdomain(host, s.config.Domain); sub != "" {
		_, ok := s.getTunnelBySubdomain(sub)
		return ok
	}
	return s.IsCustomDomainActive(host)
}
