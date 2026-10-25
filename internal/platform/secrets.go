// Package platform is the only place Sluice touches the operating system
// (SPEC.md, Platform abstraction). macOS is implemented; other platforms
// return ErrNotSupported.
package platform

import (
	"errors"
	"fmt"
	"regexp"
)

// SecretKeySize is the length of keys created by GetOrCreateKey.
const SecretKeySize = 32

// ErrNotSupported is returned on platforms without an implementation yet.
var ErrNotSupported = errors.New("platform: not supported on this OS")

// namePattern restricts Keychain service and account names to a plain
// charset. Besides being tidy, this matters for security: on macOS the names
// are written into a `security -i` command line, and a quote or newline in a
// name could otherwise inject a second command.
var namePattern = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,128}$`)

func validateNames(service, account string) error {
	if !namePattern.MatchString(service) {
		return fmt.Errorf("platform: invalid secret service name %q", service)
	}
	if !namePattern.MatchString(account) {
		return fmt.Errorf("platform: invalid secret account name %q", account)
	}
	return nil
}
