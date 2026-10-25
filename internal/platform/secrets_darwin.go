//go:build darwin

package platform

// macOS secret store backed by the login Keychain, driven through the
// built-in /usr/bin/security CLI (no new Go dependency, no CGo).
//
// The one rule that shapes this file: a secret must never be a command-line
// argument. Process arguments are visible to every local user via `ps` or
// sysctl(KERN_PROCARGS2), so `security add-generic-password -w <secret>` would
// leak the key for the lifetime of the process. Instead we start
// `security -i` (interactive mode, argv is just "-i") and write the add
// command, secret included, to its stdin pipe, which only this process can
// read. Reading the secret back with `find-generic-password -w` is fine: it
// arrives on the child's stdout pipe.
//
// Keychain access control: the item is created by /usr/bin/security, so that
// binary is on the item's trusted-app list and later reads through it do not
// show a GUI prompt. If the login keychain is locked, macOS may show an
// unlock dialog; the per-command timeout keeps us from hanging forever.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const (
	securityBin = "/usr/bin/security" // absolute: immune to $PATH hijacking

	// cmdTimeout bounds every `security` invocation. Generous, because a
	// locked keychain may put an unlock dialog in front of the user.
	cmdTimeout = 60 * time.Second

	// Exit statuses of `security`: the low byte of the OSStatus.
	exitItemNotFound = 44 // errSecItemNotFound  (-25300)
	exitDuplicate    = 45 // errSecDuplicateItem (-25299)
)

var (
	errItemNotFound = errors.New("keychain item not found")
	errDuplicate    = errors.New("keychain item already exists")
)

// GetOrCreateKey returns the 32-byte key stored under (service, account) in
// the login Keychain, creating and storing a random one if none exists.
// An existing item is never overwritten: losing a database key makes the
// project file permanently unreadable.
func GetOrCreateKey(service, account string) ([]byte, error) {
	if err := validateNames(service, account); err != nil {
		return nil, err
	}
	kc, err := loginKeychain()
	if err != nil {
		return nil, err
	}

	key, err := findKey(kc, service, account)
	if !errors.Is(err, errItemNotFound) {
		return key, err // found, or a real failure
	}

	key = make([]byte, SecretKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("platform: generate key: %w", err)
	}
	err = addKey(kc, service, account, key)
	if errors.Is(err, errDuplicate) {
		// Another process created it between our find and add; theirs wins.
		return findKey(kc, service, account)
	}
	if err != nil {
		return nil, err
	}

	// Read back before handing the key out: if the store silently failed,
	// we would encrypt a database with a key nobody can recover.
	stored, err := findKey(kc, service, account)
	if err != nil {
		return nil, fmt.Errorf("platform: verify stored key: %w", err)
	}
	if subtle.ConstantTimeCompare(stored, key) != 1 {
		return nil, errors.New("platform: stored key does not match generated key")
	}
	return key, nil
}

// DeleteKey removes the item. Deleting a missing item is not an error, so
// "wipe project" can be retried safely.
func DeleteKey(service, account string) error {
	if err := validateNames(service, account); err != nil {
		return err
	}
	kc, err := loginKeychain()
	if err != nil {
		return err
	}
	_, err = run(nil, "delete-generic-password", "-s", service, "-a", account, kc)
	if errors.Is(err, errItemNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("platform: delete keychain item: %w", err)
	}
	return nil
}

// loginKeychain asks `security` for the login keychain path, so we never
// write to (or read from) some other keychain in the user's search list.
func loginKeychain() (string, error) {
	out, err := run(nil, "login-keychain")
	if err != nil {
		return "", fmt.Errorf("platform: locate login keychain: %w", err)
	}
	// Output looks like:    "/Users/me/Library/Keychains/login.keychain-db"
	path := strings.Trim(strings.TrimSpace(string(out)), `"`)
	if path == "" || strings.ContainsAny(path, "\"\\\n\r") {
		return "", errors.New("platform: unexpected login keychain path")
	}
	return path, nil
}

// findKey reads and hex-decodes the item. The secret travels on stdout only.
func findKey(kc, service, account string) ([]byte, error) {
	out, err := run(nil, "find-generic-password", "-s", service, "-a", account, "-w", kc)
	defer clear(out)
	if err != nil {
		if errors.Is(err, errItemNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("platform: read keychain item: %w", err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(out)))
	if err != nil || len(key) != SecretKeySize {
		// Never echo the item contents in the error.
		return nil, fmt.Errorf("platform: keychain item %s/%s is not a %d-byte hex key", service, account, SecretKeySize)
	}
	return key, nil
}

func addKey(kc, service, account string, key []byte) error {
	stdin := addCommand(kc, service, account, hex.EncodeToString(key))
	defer clear(stdin)
	_, err := run(stdin, "-i")
	if err != nil && !errors.Is(err, errDuplicate) {
		return fmt.Errorf("platform: store keychain item: %w", err)
	}
	return err
}

// addCommand builds the stdin script for `security -i`. Names are validated
// against namePattern and the keychain path has no quotes, so double-quoting
// is enough. No -U flag: updating an existing item would replace its key.
func addCommand(kc, service, account, hexKey string) []byte {
	return fmt.Appendf(nil, "add-generic-password -s \"%s\" -a \"%s\" -w %s \"%s\"\n",
		service, account, hexKey, kc)
}

// run executes `security args...` with a timeout, optionally feeding stdin.
// It maps the well-known exit statuses to sentinel errors. Stderr is
// included in other errors for diagnosis; stdin is never echoed into it.
func run(stdin []byte, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()

	// G204: the binary is a constant absolute path, and args are fixed verbs,
	// validated names and the keychain path; no shell is involved.
	cmd := exec.CommandContext(ctx, securityBin, args...) //nolint:gosec // G204: see above
	// Do not wait forever on the child's pipes after a timeout kill.
	cmd.WaitDelay = time.Second
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("security %s: timed out after %s", args[0], cmdTimeout)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		switch exitErr.ExitCode() {
		case exitItemNotFound:
			return nil, errItemNotFound
		case exitDuplicate:
			return nil, errDuplicate
		}
		return nil, fmt.Errorf("security %s: exit %d: %s",
			args[0], exitErr.ExitCode(), firstLine(stderr.String()))
	}
	if err != nil {
		return nil, fmt.Errorf("security %s: %w", args[0], err)
	}
	return stdout.Bytes(), nil
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return line
}
