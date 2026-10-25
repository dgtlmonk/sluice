package platform

import (
	"crypto/x509"
	"errors"
)

// TrustReport is the CA trust health check result (SPEC.md, Platform
// abstraction). Installed and Trusted are separate on purpose: a root can
// sit in the keychain without a trust setting, and the fix differs.
type TrustReport struct {
	// Installed: the exact root certificate (by SHA-256) is in the login keychain.
	Installed bool `json:"installed"`
	// Trusted: the OS accepts a leaf minted by this root for TLS server auth.
	Trusted bool `json:"trusted"`
	// Detail explains a false Trusted (the OS verifier's reason).
	Detail string `json:"detail,omitempty"`
}

// CertTrust is the OS certificate trust store. The app gets the real one
// from SystemCertTrust; tests use fakes so nothing touches the user's
// keychain unless a test is explicitly opted in.
type CertTrust interface {
	// InstallRoot adds root to the login keychain as a trusted root. The OS
	// asks the user for their password; call this only from a user action.
	InstallRoot(root *x509.Certificate) error
	// Check reports whether root is installed, and whether probe (a leaf
	// for probeHost signed by root) verifies against the OS trust store.
	Check(root, probe *x509.Certificate, probeHost string) (TrustReport, error)
}

// validateRoot is the guard InstallRoot applies before asking the OS: only
// a self-signed CA certificate may become a trust anchor.
func validateRoot(root *x509.Certificate) error {
	if root == nil || !root.IsCA || !root.BasicConstraintsValid {
		return errors.New("platform: not a CA certificate")
	}
	if err := root.CheckSignatureFrom(root); err != nil {
		return errors.New("platform: root is not self-signed")
	}
	return nil
}
