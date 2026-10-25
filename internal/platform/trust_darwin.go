//go:build darwin

package platform

// macOS certificate trust, through /usr/bin/security like the secret store.
//
// Install: `security add-trusted-cert -r trustRoot -k <login keychain> <pem>`
// imports the certificate and adds a user-level trust setting marking it as
// a root for all policies. macOS shows a password dialog for that change;
// this is the "user-clicked install" from SPEC.md, and Sluice never runs it
// on its own.
//
// Check, two questions:
//   - installed: `security find-certificate -a -Z <login keychain>` lists
//     every certificate with its SHA-256 hash; ours must be among them.
//   - trusted: verify a freshly minted probe leaf with Go's x509 against the
//     system roots. On macOS, crypto/x509 hands that to the OS verifier
//     (SecTrustEvaluateWithError), which reads keychains and trust settings,
//     so this is the same decision Safari and Chrome make.

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"
)

// installTimeout is long: the user has to read a dialog and type a password.
const installTimeout = 3 * time.Minute

type runner func(timeout time.Duration, stdin []byte, args ...string) ([]byte, error)

type securityTrust struct {
	run      runner
	keychain func() (string, error)
	// verify is x509 verification against the system roots; swappable in tests.
	verify func(probe *x509.Certificate, host string) error
}

// SystemCertTrust returns the macOS login-keychain trust store.
func SystemCertTrust() CertTrust {
	return securityTrust{run: runTimeout, keychain: loginKeychain, verify: verifySystem}
}

func verifySystem(probe *x509.Certificate, host string) error {
	// Roots nil = the platform verifier. No intermediates: the root must be
	// found in the OS store, not handed over by us.
	_, err := probe.Verify(x509.VerifyOptions{DNSName: host})
	return err
}

func (s securityTrust) InstallRoot(root *x509.Certificate) error {
	if err := validateRoot(root); err != nil {
		return err
	}
	kc, err := s.keychain()
	if err != nil {
		return err
	}
	// `security` takes a file path. The file holds only the public
	// certificate, so a temp file is fine; remove it afterwards anyway.
	f, err := os.CreateTemp("", "sluice-ca-*.pem")
	if err != nil {
		return fmt.Errorf("platform: temp cert file: %w", err)
	}
	defer func() { _ = os.Remove(f.Name()) }()
	werr := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return fmt.Errorf("platform: write temp cert file: %w", werr)
	}
	if _, err := s.run(installTimeout, nil, installArgs(kc, f.Name())...); err != nil {
		return fmt.Errorf("platform: install CA (was the password dialog cancelled?): %w", err)
	}
	return nil
}

func installArgs(kc, pemPath string) []string {
	return []string{"add-trusted-cert", "-r", "trustRoot", "-k", kc, pemPath}
}

func (s securityTrust) Check(root, probe *x509.Certificate, probeHost string) (TrustReport, error) {
	if root == nil || probe == nil {
		return TrustReport{}, fmt.Errorf("platform: trust check needs a root and a probe")
	}
	kc, err := s.keychain()
	if err != nil {
		return TrustReport{}, err
	}
	out, err := s.run(cmdTimeout, nil, "find-certificate", "-a", "-Z", kc)
	if err != nil {
		return TrustReport{}, fmt.Errorf("platform: list keychain certificates: %w", err)
	}
	sum := sha256.Sum256(root.Raw)
	rep := TrustReport{Installed: hasSHA256(out, sum[:])}
	if verr := s.verify(probe, probeHost); verr != nil {
		rep.Detail = verr.Error()
	} else {
		rep.Trusted = true
	}
	return rep, nil
}

// hasSHA256 scans `find-certificate -Z` output for a "SHA-256 hash: <HEX>" line.
func hasSHA256(out, sum []byte) bool {
	want := strings.ToUpper(hex.EncodeToString(sum))
	for line := range strings.SplitSeq(string(out), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "SHA-256 hash:")
		if ok && strings.EqualFold(strings.TrimSpace(rest), want) {
			return true
		}
	}
	return false
}
