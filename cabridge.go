package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dgtlmonk/sluice/internal/ca"
	"github.com/dgtlmonk/sluice/internal/platform"
)

const (
	// envCADir overrides the CA folder (default: <config dir>/Sluice/ca).
	envCADir = "SLUICE_CA_DIR"
	// caKeychainService names the Keychain secret that seals the CA keys.
	caKeychainService = "dev.sluice.ca"
	// trustProbeHost is the name on the throwaway leaf the trust check
	// verifies. .invalid is reserved (RFC 6761) and never resolves.
	trustProbeHost = "trust-check.sluice.invalid"
)

// CAInfo is what Settings shows about the root CA. Only public facts.
type CAInfo struct {
	Ready       bool   `json:"ready"`
	Error       string `json:"error,omitempty"`
	Subject     string `json:"subject,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"` // SHA-256, colon-separated hex
	NotAfter    string `json:"notAfter,omitempty"`    // RFC 3339
	Dir         string `json:"dir,omitempty"`
}

// caService holds the loaded CA (or why it failed) and the OS trust store.
// Its methods are what the Wails bindings call.
type caService struct {
	trust platform.CertTrust

	mu   sync.Mutex
	auth *ca.Authority
	dir  string
	err  error
}

func newCAService(trust platform.CertTrust) *caService { return &caService{trust: trust} }

// load opens or creates the CA. A failure is kept and shown in Settings;
// the proxy still runs for plain HTTP.
func (s *caService) load(dir string, secret func(dir string) ([]byte, error)) {
	a, err := openCA(dir, secret)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auth, s.dir, s.err = a, dir, err
}

func openCA(dir string, secret func(dir string) ([]byte, error)) (*ca.Authority, error) {
	key, err := secret(dir)
	if err != nil {
		return nil, fmt.Errorf("CA secret: %w", err)
	}
	defer clear(key)
	return ca.LoadOrCreate(dir, key)
}

func (s *caService) authority() (*ca.Authority, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.err != nil:
		return nil, s.err
	case s.auth == nil:
		return nil, errors.New("CA not loaded yet")
	}
	return s.auth, nil
}

func (s *caService) info() CAInfo {
	a, err := s.authority()
	s.mu.Lock()
	dir := s.dir
	s.mu.Unlock()
	if err != nil {
		return CAInfo{Error: err.Error(), Dir: dir}
	}
	fp := a.Fingerprint()
	return CAInfo{
		Ready:       true,
		Subject:     a.Certificate().Subject.CommonName,
		Fingerprint: colonHex(fp[:]),
		NotAfter:    a.Certificate().NotAfter.UTC().Format(time.RFC3339),
		Dir:         dir,
	}
}

func (s *caService) check() (platform.TrustReport, error) {
	a, err := s.authority()
	if err != nil {
		return platform.TrustReport{}, err
	}
	probe, err := a.MintLeaf(trustProbeHost)
	if err != nil {
		return platform.TrustReport{}, err
	}
	return s.trust.Check(a.Certificate(), probe.Leaf, trustProbeHost)
}

func (s *caService) install() error {
	a, err := s.authority()
	if err != nil {
		return err
	}
	return s.trust.InstallRoot(a.Certificate())
}

// export writes the root certificate (never a key) as PEM to path.
func (s *caService) export(path string) error {
	a, err := s.authority()
	if err != nil {
		return err
	}
	// A certificate is public: 0644 so other tools (Firefox import) can read it.
	if err := os.WriteFile(path, a.CertPEM(), 0o644); err != nil { //nolint:gosec // G306: public cert
		return fmt.Errorf("export CA: %w", err)
	}
	return nil
}

// defaultCADir is ~/Library/Application Support/Sluice/ca on macOS.
func defaultCADir() (string, error) {
	if d := strings.TrimSpace(os.Getenv(envCADir)); d != "" {
		return filepath.Abs(d)
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "Sluice", "ca"), nil
}

// keychainCASecret gets (or creates) the 32-byte sealing secret for the CA
// in dir: one Keychain item per CA folder, named by a hash of the path.
func keychainCASecret(dir string) ([]byte, error) {
	sum := sha256.Sum256([]byte(dir))
	return platform.GetOrCreateKey(caKeychainService, "ca-"+hex.EncodeToString(sum[:16]))
}

func colonHex(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02X", x)
	}
	return strings.Join(parts, ":")
}
