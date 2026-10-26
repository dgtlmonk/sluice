//go:build darwin

package platform

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dgtlmonk/sluice/internal/ca"
)

func testCA(t *testing.T) (*ca.Authority, *x509.Certificate) {
	t.Helper()
	secret := make([]byte, ca.SecretSize)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	a, err := ca.LoadOrCreate(t.TempDir(), secret)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := a.MintLeaf("trust-check.sluice.invalid")
	if err != nil {
		t.Fatal(err)
	}
	return a, probe.Leaf
}

type call struct {
	timeout time.Duration
	args    []string
	pem     string // contents of the cert file, for add-trusted-cert
}

// fakeTrust records `security` calls instead of running them.
func fakeTrust(t *testing.T, listing string, verifyErr error) (securityTrust, *[]call) {
	t.Helper()
	var calls []call
	return securityTrust{
		keychain: func() (string, error) { return "/k/login.keychain-db", nil },
		verify:   func(*x509.Certificate, string) error { return verifyErr },
		run: func(timeout time.Duration, stdin []byte, args ...string) ([]byte, error) {
			c := call{timeout: timeout, args: args}
			if args[0] == "add-trusted-cert" {
				b, err := os.ReadFile(args[len(args)-1])
				if err != nil {
					t.Errorf("cert file not readable during install: %v", err)
				}
				c.pem = string(b)
			}
			calls = append(calls, c)
			return []byte(listing), nil
		},
	}, &calls
}

func TestInstallRootCommand(t *testing.T) {
	a, _ := testCA(t)
	s, calls := fakeTrust(t, "", nil)
	if err := s.InstallRoot(a.Certificate()); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 {
		t.Fatalf("%d calls", len(*calls))
	}
	c := (*calls)[0]
	want := []string{"add-trusted-cert", "-r", "trustRoot", "-p", "ssl", "-k", "/k/login.keychain-db"}
	if strings.Join(c.args[:len(want)], " ") != strings.Join(want, " ") {
		t.Errorf("args %q", c.args)
	}
	if c.pem != string(a.CertPEM()) {
		t.Error("installed file is not exactly the root PEM")
	}
	if strings.Contains(c.pem, "PRIVATE") {
		t.Error("private key in install file")
	}
	if _, err := os.Stat(c.args[5]); !errors.Is(err, os.ErrNotExist) {
		t.Error("temp cert file not removed")
	}
	if c.timeout < time.Minute {
		t.Errorf("install timeout %v too short for a password dialog", c.timeout)
	}
}

func TestInstallRootRejectsLeaf(t *testing.T) {
	_, probe := testCA(t)
	s, calls := fakeTrust(t, "", nil)
	if s.InstallRoot(probe) == nil {
		t.Fatal("installed a non-CA certificate")
	}
	if len(*calls) != 0 {
		t.Fatal("security was called")
	}
}

func TestCheckReportsInstalledAndTrusted(t *testing.T) {
	a, probe := testCA(t)
	sum := sha256.Sum256(a.Certificate().Raw)
	listing := "keychain: \"/k/login.keychain-db\"\nSHA-256 hash: 00AA\nSHA-256 hash: " +
		strings.ToUpper(hex.EncodeToString(sum[:])) + "\nSHA-1 hash: 1234\n"

	cases := []struct {
		name      string
		listing   string
		verifyErr error
		want      TrustReport
	}{
		{"installed+trusted", listing, nil, TrustReport{Installed: true, Trusted: true}},
		{"installed, not trusted", listing, errors.New("x509: not trusted"), TrustReport{Installed: true, Detail: "x509: not trusted"}},
		{"absent", "SHA-256 hash: 00AA\n", errors.New("x509: unknown authority"), TrustReport{Detail: "x509: unknown authority"}},
	}
	for _, tc := range cases {
		s, _ := fakeTrust(t, tc.listing, tc.verifyErr)
		got, err := s.Check(a.Certificate(), probe, "trust-check.sluice.invalid")
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got != tc.want {
			t.Errorf("%s: got %+v want %+v", tc.name, got, tc.want)
		}
	}
}

// TestSystemTrustCheck is read-only against the real login keychain (no
// install), and still opt-in like the Keychain test:
//
//	SLUICE_KEYCHAIN_TEST=1 go test ./internal/platform/ -run SystemTrust -v
//
// A fresh test CA is never installed, so it must report not installed, not trusted.
func TestSystemTrustCheck(t *testing.T) {
	if os.Getenv("SLUICE_KEYCHAIN_TEST") != "1" {
		t.Skip("set SLUICE_KEYCHAIN_TEST=1 to run against the real login keychain")
	}
	a, probe := testCA(t)
	rep, err := SystemCertTrust().Check(a.Certificate(), probe, "trust-check.sluice.invalid")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Installed || rep.Trusted || rep.Detail == "" {
		t.Fatalf("fresh CA reported %+v", rep)
	}
}
