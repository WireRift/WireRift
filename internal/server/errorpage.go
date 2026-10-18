package server

import (
	"fmt"
	"html"
	"net/http"
	"strings"
)

// wantsHTML reports whether the client is a browser asking for a page.
func wantsHTML(r *http.Request) bool {
	return r != nil && r.Method != http.MethodHead && strings.Contains(r.Header.Get("Accept"), "text/html")
}

// defaultHint returns a short explanation for common edge errors.
func defaultHint(status int, message string) string {
	switch {
	case message == "Tunnel not found":
		return "No tunnel is registered for this address. Check the URL, or start the tunnel again."
	case message == "Session not found":
		return "The client that owned this tunnel has disconnected. Start it again to bring the tunnel back."
	case status == http.StatusBadGateway:
		return "The tunnel is up, but the tunnel client did not answer. Make sure the local app is running, then refresh."
	case status == http.StatusRequestEntityTooLarge:
		return "The request body is larger than the tunnel allows."
	case status == http.StatusTooManyRequests:
		return "Too many requests from your address. Wait a moment and try again."
	case status == http.StatusForbidden:
		return "Your address is not allowed to use this tunnel."
	}
	return ""
}

// writeEdgeError reports an edge error. Browsers get a small self-contained
// HTML page; everything else gets the plain-text body net/http would send, so
// API clients and scripts see exactly the same responses as before.
func writeEdgeError(w http.ResponseWriter, r *http.Request, status int, message string) {
	if !wantsHTML(r) {
		http.Error(w, message, status)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.WriteHeader(status)
	text := html.EscapeString(http.StatusText(status))
	fmt.Fprintf(w, errorPageHTML,
		status, text, // <title>
		status, text, // eyebrow
		html.EscapeString(message), html.EscapeString(defaultHint(status, message)))
}

const errorPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%d %s - WireRift</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:40px;max-width:480px;width:90%%}
.code{font-size:14px;color:#818cf8;font-weight:600;margin-bottom:8px}
h1{font-size:22px;margin-bottom:12px;color:#fff}
p{color:#94a3b8;font-size:15px;line-height:1.5}
.brand{margin-top:24px;font-size:12px;color:#64748b}
</style>
</head>
<body>
<div class="card">
<div class="code">%d %s</div>
<h1>%s</h1>
<p>%s</p>
<div class="brand">WireRift</div>
</div>
</body>
</html>`
