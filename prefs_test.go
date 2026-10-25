package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenPrefsDefaults(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"missing":   "",
		"garbage":   "{not json",
		"wrongType": `{"theme": 7}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".json")
			if body != "" {
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if got := openPrefs(path).get(); got != defaultPrefs() {
				t.Fatalf("got %+v, want defaults", got)
			}
		})
	}
}

func TestOpenPrefsValidates(t *testing.T) {
	cases := []struct {
		body string
		want Prefs
	}{
		{`{"theme":"light","fontSize":14}`, Prefs{ThemeLight, 14}},
		{`{"theme":"neon","fontSize":14}`, Prefs{ThemeSystem, 14}}, // unknown theme
		{`{"theme":"dark","fontSize":400}`, Prefs{ThemeDark, 16}},  // clamped high
		{`{"theme":"dark","fontSize":-3}`, Prefs{ThemeDark, 11}},   // clamped low
		{`{"theme":"dark","fontSize":15}`, Prefs{ThemeDark, 14}},   // snapped, tie goes down
		{`{"theme":"dark"}`, Prefs{ThemeDark, defaultFontSize}},    // field missing
	}
	for _, c := range cases {
		path := filepath.Join(t.TempDir(), "prefs.json")
		if err := os.WriteFile(path, []byte(c.body), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := openPrefs(path).get(); got != c.want {
			t.Errorf("%s: got %+v, want %+v", c.body, got, c.want)
		}
	}
}

func TestPrefsUpdateSavesAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "prefs.json")
	s := openPrefs(path)
	next, changed, err := s.update(func(p Prefs) Prefs { p.Theme, p.FontSize = ThemeLight, 13; return p })
	if err != nil || !changed || next != (Prefs{ThemeLight, 13}) {
		t.Fatalf("update = %+v %v %v", next, changed, err)
	}
	if _, changed, _ := s.update(func(p Prefs) Prefs { return p }); changed {
		t.Fatal("no-op update reported a change")
	}
	if got := openPrefs(path).get(); got != next {
		t.Fatalf("reloaded %+v, want %+v", got, next)
	}
	b, err := os.ReadFile(path) //nolint:gosec // G304: test temp file
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil || raw["theme"] != "light" {
		t.Fatalf("file %s: %v", b, err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}

func TestPrefsUpdateSaveFailureStillApplies(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s := openPrefs(filepath.Join(blocker, "prefs.json")) // parent is a file: save fails
	next, changed, err := s.update(func(p Prefs) Prefs { p.Theme = ThemeDark; return p })
	if err == nil || !changed || s.get() != next || next.Theme != ThemeDark {
		t.Fatalf("got %+v %v %v", next, changed, err)
	}
}

func TestStepFontSize(t *testing.T) {
	cases := []struct{ cur, delta, want int }{
		{12, +1, 13}, {14, +1, 16}, {16, +1, 16}, {11, -1, 11}, {12, -1, 11}, {15, +1, 16}, {99, -1, 14},
	}
	for _, c := range cases {
		if got := stepFontSize(c.cur, c.delta); got != c.want {
			t.Errorf("stepFontSize(%d,%d) = %d, want %d", c.cur, c.delta, got, c.want)
		}
	}
}

func TestSetPrefsRejectsUnknownTheme(t *testing.T) {
	a := &App{prefs: openPrefs("")}
	if _, err := a.SetPrefs(Prefs{Theme: "neon", FontSize: 12}); err == nil {
		t.Fatal("want error")
	}
	got, err := a.SetPrefs(Prefs{Theme: ThemeLight, FontSize: 50})
	if err != nil || got != (Prefs{ThemeLight, 16}) {
		t.Fatalf("got %+v %v", got, err)
	}
}

func TestPrefsFilePathEnv(t *testing.T) {
	want := filepath.Join(t.TempDir(), "p.json")
	t.Setenv(envPrefsFile, want)
	if got, err := prefsFilePath(); err != nil || got != want {
		t.Fatalf("got %q %v", got, err)
	}
}
