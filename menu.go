package main

import (
	"context"
	"sync"

	"github.com/wailsapp/wails/v2/pkg/menu"
	"github.com/wailsapp/wails/v2/pkg/menu/keys"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// eventMenuSettings asks the UI to open the Settings panel (App menu, Cmd+,).
const eventMenuSettings = "menu:settings"

// appMenu is the native main menu. Wails menus are UI shell, not OS calls in
// the internal/platform sense: the menu package is cross-platform (on macOS
// the first submenu becomes the application menu).
type appMenu struct {
	mu     sync.Mutex
	root   *menu.Menu
	themes map[string]*menu.MenuItem // View > Theme radio items, by theme
}

// buildMenu creates the main menu. Its callbacks run on Wails' menu goroutine
// and go through the same prefs path as the bindings.
func (a *App) buildMenu() *menu.Menu {
	root := menu.NewMenu()

	// App menu. Built by hand rather than with menu.AppMenu() because that
	// role has no Settings item.
	app := root.AddSubmenu("Sluice")
	app.AddText("About Sluice", nil, func(*menu.CallbackData) { a.showAbout() })
	app.AddSeparator()
	app.AddText("Settings…", keys.CmdOrCtrl(","), func(*menu.CallbackData) {
		if ctx := a.uiContext(); ctx != nil {
			runtime.EventsEmit(ctx, eventMenuSettings)
		}
	})
	app.AddSeparator()
	app.AddText("Hide Sluice", keys.CmdOrCtrl("h"), func(*menu.CallbackData) {
		if ctx := a.uiContext(); ctx != nil {
			runtime.Hide(ctx)
		}
	})
	app.AddSeparator()
	app.AddText("Quit Sluice", keys.CmdOrCtrl("q"), func(*menu.CallbackData) {
		if ctx := a.uiContext(); ctx != nil {
			runtime.Quit(ctx)
		}
	})

	file := root.AddSubmenu("File")
	file.AddText("Export CA Certificate…", keys.CmdOrCtrl("e"), func(*menu.CallbackData) {
		if _, err := a.ExportCA(); err != nil {
			a.showError("Export failed", err)
		}
	})

	// Edit role: Undo/Redo/Cut/Copy/Paste/Select All wired to the responder
	// chain, so the shortcuts work in the webview's text fields and panes.
	root.Append(menu.EditMenu())

	view := root.AddSubmenu("View")
	// Ctrl+= / Ctrl+- / Ctrl+0 are handled in the webview (useFontShortcuts),
	// because a menu item takes only one accelerator.
	step := func(delta int) menu.Callback {
		return func(*menu.CallbackData) { _, _ = a.StepFontSize(delta) }
	}
	view.AddText("Bigger Text", keys.CmdOrCtrl("="), step(+1))
	view.AddText("Smaller Text", keys.CmdOrCtrl("-"), step(-1))
	view.AddText("Actual Size", keys.CmdOrCtrl("0"), step(0))
	view.AddSeparator()
	themeMenu := view.AddSubmenu("Theme")
	cur := a.prefs.get().Theme
	themes := map[string]*menu.MenuItem{}
	for _, t := range []struct{ id, label string }{{ThemeSystem, "System"}, {ThemeDark, "Dark"}, {ThemeLight, "Light"}} {
		themes[t.id] = themeMenu.AddRadio(t.label, cur == t.id, nil, func(*menu.CallbackData) {
			_, _ = a.changePrefs(func(p Prefs) Prefs { p.Theme = t.id; return p })
		})
	}

	// Window role: Minimize (Cmd+M), Zoom, Full Screen (Ctrl+Cmd+F).
	root.Append(menu.WindowMenu())

	help := root.AddSubmenu("Help")
	help.AddText("Learning Notes", nil, func(*menu.CallbackData) {
		if ctx := a.uiContext(); ctx != nil {
			runtime.BrowserOpenURL(ctx, learnNotesURL)
		}
	})

	a.menu.mu.Lock()
	a.menu.root, a.menu.themes = root, themes
	a.menu.mu.Unlock()
	return root
}

// syncMenu moves the Theme radio check to p.Theme and redraws the menu.
func (a *App) syncMenu(p Prefs) {
	a.menu.mu.Lock()
	defer a.menu.mu.Unlock()
	if a.menu.root == nil {
		return
	}
	for id, item := range a.menu.themes {
		item.SetChecked(id == p.Theme)
	}
	if ctx := a.uiContext(); ctx != nil {
		runtime.MenuUpdateApplicationMenu(ctx)
	}
}

func (a *App) showAbout() {
	ctx := a.uiContext()
	if ctx == nil {
		return
	}
	_, _ = runtime.MessageDialog(ctx, runtime.MessageDialogOptions{
		Type:    runtime.InfoDialog,
		Title:   "About Sluice",
		Message: "Sluice: a local intercepting proxy for learning HTTP and TLS.\nListens on loopback only.",
	})
}

// learnNotesURL is the docs/learn index on GitHub (Help > Learning Notes).
const learnNotesURL = "https://github.com/dgtlmonk/sluice/tree/main/docs/learn"

func (a *App) showError(title string, err error) {
	ctx := a.uiContext()
	if ctx == nil {
		return
	}
	_, _ = runtime.MessageDialog(ctx, runtime.MessageDialogOptions{
		Type:    runtime.ErrorDialog,
		Title:   title,
		Message: err.Error(),
	})
}

// uiContext returns the Wails context once startup has run, else nil.
func (a *App) uiContext() context.Context {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.wailsCtx
}
