package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
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

// No scope file yet means the default scope; a saved list round-trips,
// including an explicitly empty one; a bad file fails closed (empty) and
// says why.
func TestScopeListRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "scope.json")
	t.Setenv(envScopeFile, path)
	if got, err := loadScopeList(); err != nil || !slices.Equal(got, engine.DefaultScope) {
		t.Fatalf("missing file: %v %v", got, err)
	}
	if err := saveScopeList([]string{"a.test", "*.b.test"}); err != nil {
		t.Fatal(err)
	}
	if got, err := loadScopeList(); err != nil || !slices.Equal(got, []string{"a.test", "*.b.test"}) {
		t.Fatalf("loaded %v %v", got, err)
	}
	if err := saveScopeList(nil); err != nil {
		t.Fatal(err)
	}
	if got, err := loadScopeList(); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("saved empty list loaded as %v %v", got, err)
	}
	for _, bad := range []string{`not json`, `["http://evil.example/"]`} {
		if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := loadScopeList(); err == nil || got == nil || len(got) != 0 {
			t.Fatalf("bad file %q loaded as %v, %v (want empty and an error: fail closed, loudly)", bad, got, err)
		}
	}
	if err := saveScopeList([]string{"a.test"}); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("scope file mode: %v %v", st.Mode(), err)
	}
	// Each write uses its own temp file and leaves none behind.
	if left, _ := filepath.Glob(path + ".*.tmp"); len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}
}

// A corrupt scope.json reaches Settings as LoadError (with an empty,
// fail-closed list), and a good save clears it.
func TestAppScopeLoadErrorShownThenCleared(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scope.json")
	t.Setenv(envScopeFile, path)
	if err := os.WriteFile(path, []byte(`{broken`), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &App{proxy: newProxyBridge("127.0.0.1:0", func() int64 { return 1 })}
	a.loadScope()
	st := a.ScopeHosts()
	if len(st.Hosts) != 0 || !strings.Contains(st.LoadError, "scope.json") || !strings.Contains(st.LoadError, "refused") {
		t.Fatalf("after corrupt file: %+v", st)
	}
	st, err := a.SetScopeHosts([]string{"a.test", "*.com"})
	if err != nil || st.LoadError != "" || !slices.Equal(st.Hosts, []string{"a.test", "*.com"}) || len(st.Warnings) != 1 {
		t.Fatalf("after save: %+v %v", st, err)
	}
	if got, err := loadScopeList(); err != nil || !slices.Equal(got, st.Hosts) {
		t.Fatalf("saved file %v %v", got, err)
	}
}

// Concurrent saves: whichever wins, the file holds the list the engine
// enforces (apply and save are one step under settingsMu).
func TestAppSetScopeHostsSerialized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scope.json")
	t.Setenv(envScopeFile, path)
	a := &App{proxy: newProxyBridge("127.0.0.1:0", func() int64 { return 1 })}
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := a.SetScopeHosts([]string{"h" + strconv.Itoa(i) + ".test"}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	saved, err := loadScopeList()
	if err != nil || !slices.Equal(saved, a.ScopeHosts().Hosts) {
		t.Fatalf("file %v (%v) != live %v", saved, err, a.ScopeHosts().Hosts)
	}
	if left, _ := filepath.Glob(path + ".*.tmp"); len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}
}

func TestBridgeScopeDefaultsAndValidates(t *testing.T) {
	b := newProxyBridge("127.0.0.1:0", func() int64 { return 1 })
	if !slices.Equal(b.scopeHosts(), engine.DefaultScope) {
		t.Fatalf("default scope %v", b.scopeHosts())
	}
	if _, err := b.setScope([]string{"a.test:8080"}); err == nil {
		t.Fatal("pattern with port accepted")
	}
	if !slices.Equal(b.scopeHosts(), engine.DefaultScope) {
		t.Fatal("a refused list changed the scope")
	}
	got, err := b.setScope([]string{" A.test. ", "*.Lab.test"})
	if err != nil || !slices.Equal(got, []string{"a.test", "*.lab.test"}) || !slices.Equal(b.scopeHosts(), got) {
		t.Fatalf("got %v, %v", got, err)
	}
	// The bridge's scope is what the engine enforces: the change is live.
	if _, err := b.scope.Check(engine.Target{Scheme: "http", Host: "localhost", Port: 80}); !errors.Is(err, engine.ErrOutOfScope) {
		t.Fatalf("localhost after narrowing: %v", err)
	}
}
