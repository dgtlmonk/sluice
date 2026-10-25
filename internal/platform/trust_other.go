//go:build !darwin

package platform

import "crypto/x509"

type unsupportedTrust struct{}

// SystemCertTrust is not implemented on this OS yet.
func SystemCertTrust() CertTrust { return unsupportedTrust{} }

func (unsupportedTrust) InstallRoot(root *x509.Certificate) error {
	if err := validateRoot(root); err != nil {
		return err
	}
	return ErrNotSupported
}

func (unsupportedTrust) Check(_, _ *x509.Certificate, _ string) (TrustReport, error) {
	return TrustReport{}, ErrNotSupported
}
