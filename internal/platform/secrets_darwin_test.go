//go:build darwin

package platform

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// TestAddCommandScript checks the stdin script for `security -i`: the secret
// travels there (argv is only "-i"), as exactly one command, without -U.
func TestAddCommandScript(t *testing.T) {
	const hexKey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	script := string(addCommand("/Users/me/Library/Keychains/login.keychain-db", "dev.sluice.p1", "db", hexKey))

	want := `add-generic-password -s "dev.sluice.p1" -a "db" -w ` + hexKey +
		` "/Users/me/Library/Keychains/login.keychain-db"` + "\n"
	if script != want {
		t.Fatalf("script:\n got %q\nwant %q", script, want)
	}
}

func TestValidateNamesRejectsInjection(t *testing.T) {
	bad := []string{"", "a b", `a"b`, "a\nadd-generic-password", "a;b", strings.Repeat("a", 129)}
	for _, name := range bad {
		if validateNames(name, "ok") == nil {
			t.Errorf("service %q accepted", name)
		}
		if validateNames("ok", name) == nil {
			t.Errorf("account %q accepted", name)
		}
	}
	if err := validateNames("dev.sluice.project-1", "db@local_2"); err != nil {
		t.Errorf("valid names rejected: %v", err)
	}
}

// TestKeychainRoundTrip touches the real login Keychain, so it is opt-in:
//
//	SLUICE_KEYCHAIN_TEST=1 go test ./internal/platform/ -run Keychain -v
func TestKeychainRoundTrip(t *testing.T) {
	if os.Getenv("SLUICE_KEYCHAIN_TEST") != "1" {
		t.Skip("set SLUICE_KEYCHAIN_TEST=1 to run against the real login Keychain")
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	service := "dev.sluice.test." + hex.EncodeToString(suffix) // throwaway
	const account = "db"
	t.Cleanup(func() {
		if err := DeleteKey(service, account); err != nil {
			t.Errorf("cleanup DeleteKey: %v", err)
		}
	})

	first, err := GetOrCreateKey(service, account)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(first) != SecretKeySize {
		t.Fatalf("key length %d, want %d", len(first), SecretKeySize)
	}

	again, err := GetOrCreateKey(service, account)
	if err != nil {
		t.Fatalf("get existing: %v", err)
	}
	if !bytes.Equal(first, again) {
		t.Fatal("second call returned a different key; existing item was not reused")
	}

	if err := DeleteKey(service, account); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := DeleteKey(service, account); err != nil {
		t.Fatalf("delete of missing item should be a no-op: %v", err)
	}

	fresh, err := GetOrCreateKey(service, account)
	if err != nil {
		t.Fatalf("recreate: %v", err)
	}
	if bytes.Equal(first, fresh) {
		t.Fatal("recreated key equals the deleted one")
	}
}
