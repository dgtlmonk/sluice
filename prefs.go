package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// Appearance preferences: theme and base font size. The Go side owns them so
// the native menu and the React UI read and write one copy; every change is
// broadcast as eventPrefsChanged.

const (
	ThemeSystem = "system" // follow macOS appearance (prefers-color-scheme)
	ThemeDark   = "dark"
	ThemeLight  = "light"

	defaultFontSize   = 12
	eventPrefsChanged = "prefs:changed"
	// envPrefsFile overrides where preferences are kept.
	envPrefsFile = "SLUICE_PREFS_FILE"
)

// fontSizes are the base sizes the UI offers, smallest first. "Bigger" and
// "Smaller" step through this list; anything else is clamped onto it.
var fontSizes = []int{11, 12, 13, 14, 16}

// Prefs is the persisted appearance state (prefs.json and the Wails binding).
type Prefs struct {
	Theme    string `json:"theme"`
	FontSize int    `json:"fontSize"`
}

func defaultPrefs() Prefs { return Prefs{Theme: ThemeSystem, FontSize: defaultFontSize} }

func validTheme(t string) bool { return t == ThemeSystem || t == ThemeDark || t == ThemeLight }

// normalized maps any input onto a valid Prefs: an unknown theme becomes
// System and the font size snaps to the nearest offered size (ties go down).
func (p Prefs) normalized() Prefs {
	if !validTheme(p.Theme) {
		p.Theme = ThemeSystem
	}
	p.FontSize = nearestFontSize(p.FontSize)
	return p
}

func nearestFontSize(n int) int {
	best := fontSizes[0]
	for _, s := range fontSizes[1:] {
		if abs(s-n) < abs(best-n) {
			best = s
		}
	}
	return best
}

// stepFontSize moves delta steps along fontSizes from cur, stopping at either end.
func stepFontSize(cur, delta int) int {
	i := indexOf(fontSizes, nearestFontSize(cur)) + delta
	i = max(0, min(len(fontSizes)-1, i))
	return fontSizes[i]
}

func indexOf(xs []int, v int) int {
	for i, x := range xs {
		if x == v {
			return i
		}
	}
	return -1
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// prefsStore holds the current prefs and the file they persist to.
type prefsStore struct {
	mu   sync.Mutex
	path string // "" when no config dir could be found: changes stay in memory
	cur  Prefs
}

// openPrefs loads prefs from path. A missing file means defaults; a bad one
// is logged and replaced by defaults (fields that parse are kept, then
// normalized), so the app always starts.
func openPrefs(path string) *prefsStore {
	s := &prefsStore{path: path, cur: defaultPrefs()}
	if path == "" {
		return s
	}
	b, err := os.ReadFile(path) //nolint:gosec // G304: our own settings file
	if errors.Is(err, os.ErrNotExist) {
		return s
	}
	if err != nil {
		log.Printf("prefs %s ignored: %v", path, err)
		return s
	}
	p := defaultPrefs()
	if err := json.Unmarshal(b, &p); err != nil {
		log.Printf("prefs %s ignored: %v", path, err)
		return s
	}
	s.cur = p.normalized()
	return s
}

func (s *prefsStore) get() Prefs {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur
}

// update applies fn to the current prefs, normalizes the result and saves it.
// The new value is applied even if the save fails (the UI should not refuse
// a theme change because the disk is full); the save error is returned so
// the caller can surface it. changed reports whether anything differs.
func (s *prefsStore) update(fn func(Prefs) Prefs) (next Prefs, changed bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next = fn(s.cur).normalized()
	if next == s.cur {
		return next, false, nil
	}
	s.cur = next
	if s.path != "" {
		err = savePrefs(s.path, next)
	}
	return next, true, err
}

func savePrefs(path string, p Prefs) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path) // atomic: never a half-written file
}

// prefsFilePath is ~/Library/Application Support/Sluice/prefs.json on macOS.
func prefsFilePath() (string, error) {
	if p := strings.TrimSpace(os.Getenv(envPrefsFile)); p != "" {
		return filepath.Abs(p)
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "Sluice", "prefs.json"), nil
}

// loadPrefsStore opens the prefs file at its usual location.
func loadPrefsStore() *prefsStore {
	path, err := prefsFilePath()
	if err != nil {
		log.Printf("prefs: %v (changes will not be saved)", err)
		path = ""
	}
	return openPrefs(path)
}

// Prefs returns the current appearance preferences.
func (a *App) Prefs() Prefs { return a.prefs.get() }

// SetPrefs validates, applies and saves appearance preferences, then
// broadcasts them. An unknown theme is an error; the font size is clamped
// onto the offered sizes. The applied value is returned either way.
func (a *App) SetPrefs(p Prefs) (Prefs, error) {
	if !validTheme(p.Theme) {
		return a.prefs.get(), fmt.Errorf("unknown theme %q", p.Theme)
	}
	return a.changePrefs(func(Prefs) Prefs { return p })
}

// StepFontSize moves the text size one offered step up (delta > 0) or down
// (delta < 0); delta 0 resets it. Shared by the View menu (Cmd) and the
// webview's Ctrl shortcuts.
func (a *App) StepFontSize(delta int) (Prefs, error) {
	return a.changePrefs(func(p Prefs) Prefs {
		if delta == 0 {
			p.FontSize = defaultFontSize
		} else {
			p.FontSize = stepFontSize(p.FontSize, delta)
		}
		return p
	})
}

// changePrefs is the one path every change takes (bindings and menu), so the
// file, the menu checkmarks and the UI never disagree.
func (a *App) changePrefs(fn func(Prefs) Prefs) (Prefs, error) {
	next, changed, err := a.prefs.update(fn)
	if err != nil {
		log.Printf("prefs: save: %v", err)
		err = fmt.Errorf("preferences applied but not saved: %w", err)
	}
	if changed {
		a.syncMenu(next)
		if ctx := a.uiContext(); ctx != nil {
			runtime.EventsEmit(ctx, eventPrefsChanged, next)
		}
	}
	return next, err
}
