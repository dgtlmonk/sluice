package main

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/dgtlmonk/sluice/internal/engine"
	"github.com/dgtlmonk/sluice/internal/platform"
)

func TestTrustCacheReusesResult(t *testing.T) {
	calls := 0
	c := &trustCache{ttl: time.Hour, check: func() (platform.TrustReport, error) {
		calls++
		return platform.TrustReport{Installed: true, Trusted: true}, nil
	}}
	first, second := c.trusted(), c.trusted()
	if !first || !second || calls != 1 {
		t.Fatalf("trusted twice with %d checks", calls)
	}
	c = &trustCache{ttl: 0, check: func() (platform.TrustReport, error) {
		calls++
		return platform.TrustReport{}, errors.New("no CA")
	}}
	if c.trusted() {
		t.Fatal("a failed check counted as trusted")
	}
}

func TestBypassListRoundTrip(t *testing.T) {
	t.Setenv(envBypassFile, filepath.Join(t.TempDir(), "sub", "bypass.json"))
	if got := loadBypassList(); got != nil {
		t.Fatalf("missing file: %v", got)
	}
	if err := saveBypassList([]string{"a.test", "*.b.test"}); err != nil {
		t.Fatal(err)
	}
	if got := loadBypassList(); !slices.Equal(got, []string{"a.test", "*.b.test"}) {
		t.Fatalf("loaded %v", got)
	}
}

func TestBridgeSetBypassValidates(t *testing.T) {
	b := newProxyBridge("127.0.0.1:0", func() int64 { return 1 })
	if _, err := b.setBypass([]string{"http://x"}); err == nil {
		t.Fatal("invalid pattern accepted")
	}
	got, err := b.setBypass([]string{" A.test "})
	if err != nil || !slices.Equal(got, []string{"a.test"}) || !slices.Equal(b.bypassHosts(), got) {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestTLSMetaIndexEvictsOldest(t *testing.T) {
	var m tlsMetaIndex
	for i := range int64(maxTLSMeta + 5) {
		m.put(i, ExchangeTLS{JA4: "x"})
	}
	if len(m.byID) != maxTLSMeta {
		t.Fatalf("%d entries", len(m.byID))
	}
	if _, ok := m.byID[0]; ok {
		t.Fatal("oldest entry kept")
	}
	if m.byID[maxTLSMeta+4].JA4 != "x" {
		t.Fatal("newest entry lost")
	}
}

// An unused CONNECT carries its flag to the detail pane even without a JA4
// (closed before the ClientHello), so the note is shown muted, not red.
func TestTLSFactsCarriesUnused(t *testing.T) {
	if f, ok := tlsFacts(engine.Exchange{Unused: true}); !ok || !f.Unused || f.PinSuspected {
		t.Fatalf("got %+v %v", f, ok)
	}
	if _, ok := tlsFacts(engine.Exchange{Scheme: "http"}); ok {
		t.Fatal("plain HTTP row got TLS facts")
	}
}
