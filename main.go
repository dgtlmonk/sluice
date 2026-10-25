package main

import (
	"embed"
	"fmt"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := NewApp()

	err := wails.Run(&options.App{
		Title:     "Sluice",
		Width:     1440,
		Height:    900,
		MinWidth:  900,
		MinHeight: 560,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		// Matches --bg in frontend/src/style.css so there is no flash on load.
		// The UI updates it live when the theme changes.
		BackgroundColour: startupBackground(app.Prefs().Theme),
		Menu:             app.buildMenu(),
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		Bind: []interface{}{
			app,
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "sluice:", err)
		os.Exit(1)
	}
}

// startupBackground is the window colour before the webview paints. System
// cannot be resolved here without an OS call, so it starts dark (the UI
// corrects it on first paint).
func startupBackground(theme string) *options.RGBA {
	if theme == ThemeLight {
		return &options.RGBA{R: 255, G: 255, B: 255, A: 1} // --bg, light palette
	}
	return &options.RGBA{R: 14, G: 16, B: 20, A: 1} // --bg, dark palette
}
