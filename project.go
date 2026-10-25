package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dgtlmonk/sluice/internal/platform"
	"github.com/dgtlmonk/sluice/internal/storage"
)

// envProject overrides the project file path. Until the UI has project
// management, the app opens one default project.
const envProject = "SLUICE_PROJECT"

// keychainService names Sluice's database keys in the login Keychain.
const keychainService = "dev.sluice.project"

// defaultProjectPath is ~/Library/Application Support/Sluice/default.sluice
// on macOS.
func defaultProjectPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "Sluice", "default.sluice"), nil
}

// openProject opens (creating if needed) the encrypted project store. The
// 32-byte key comes from the Keychain, is handed to storage.Open (which
// applies it with PRAGMA hexkey on each connection) and is wiped from this
// buffer afterwards. It never touches a file, a log or a command line.
func openProject() (*storage.Store, error) {
	path := strings.TrimSpace(os.Getenv(envProject))
	if path == "" {
		var err error
		if path, err = defaultProjectPath(); err != nil {
			return nil, fmt.Errorf("project path: %w", err)
		}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("project path: %w", err)
	}
	// G703: the path is the user's own choice (env or their config dir);
	// creating its directory is the point.
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil { //nolint:gosec // G703: see above
		return nil, fmt.Errorf("project directory: %w", err)
	}
	key, err := platform.GetOrCreateKey(keychainService, keychainAccount(abs))
	if err != nil {
		return nil, fmt.Errorf("project key: %w", err)
	}
	defer clear(key)
	return storage.Open(abs, key)
}

// keychainAccount derives the Keychain account name for a project file:
// one key per project, and a name that fits the platform's strict charset
// whatever characters the path holds. The hash identifies the path; it does
// not need to be secret.
func keychainAccount(absPath string) string {
	sum := sha256.Sum256([]byte(absPath))
	return "project-" + hex.EncodeToString(sum[:16])
}
