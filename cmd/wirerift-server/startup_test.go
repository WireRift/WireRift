package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestApplyEnvAddrsRespectsGivenFlags(t *testing.T) {
	t.Setenv("WIRERIFT_DOMAIN", "env.example")
	t.Setenv("WIRERIFT_CONTROL_ADDR", ":1111")
	t.Setenv("WIRERIFT_HTTP_ADDR", ":2222")
	d, c, h := "flag.example", ":4443", ":80"
	applyEnvAddrs(map[string]bool{"domain": true}, &d, &c, &h)
	if d != "flag.example" || c != ":1111" || h != ":2222" {
		t.Errorf("got %q %q %q", d, c, h)
	}
}

func TestNewLoggerLevels(t *testing.T) {
	for _, tc := range []struct{ v, j bool }{{false, false}, {true, false}, {false, true}} {
		if newLogger(tc.v, tc.j) == nil {
			t.Fatal("nil logger")
		}
	}
}

func TestPrintStartupBannerShowsQuickStart(t *testing.T) {
	var buf bytes.Buffer
	printStartupBanner(&buf, bannerInfo{Control: ":4443", HTTP: ":80", Domain: "x.test", DashPort: 4040, DashTLS: true, ControlTLS: true, DevToken: "tok_abc"})
	out := buf.String()
	for _, want := range []string{"https://localhost:4040", "-server tls://localhost:4443", "x.test"} {
		if !strings.Contains(out, want) {
			t.Errorf("banner lacks %q:\n%s", want, out)
		}
	}
}
