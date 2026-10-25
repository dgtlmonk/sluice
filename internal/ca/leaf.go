package ca

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// LeafValidity is about 397 days. Apple rejects TLS server certificates
// valid for more than 398 days (public roots) or 825 days (user-added
// roots); 397 stays under both, with a day of margin for clock skew.
const LeafValidity = 397 * 24 * time.Hour

// MintLeaf signs a certificate for host with the root CA, using the shared
// leaf key. host is a DNS name or an IP literal (it goes into the right
// Subject Alternative Name type; browsers ignore the Common Name).
//
// The result is ready for crypto/tls: Certificate holds [leaf, root] so the
// client receives the full chain, and PrivateKey is the shared leaf key.
// Caching per host is the caller's job (M3 MITM).
func (a *Authority) MintLeaf(host string) (*tls.Certificate, error) {
	return a.mintLeaf(host, time.Now())
}

func (a *Authority) mintLeaf(host string, now time.Time) (*tls.Certificate, error) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" || len(host) > 253 {
		return nil, errors.New("ca: invalid leaf host")
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := leafTemplate(host, serial, now, keyID(&a.leafKey.PublicKey))
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.root, &a.leafKey.PublicKey, a.rootKey)
	if err != nil {
		return nil, fmt.Errorf("ca: sign leaf for %s: %w", host, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("ca: parse leaf: %w", err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, a.root.Raw},
		PrivateKey:  a.leafKey,
		Leaf:        leaf,
	}, nil
}

// leafTemplate is the per-host certificate shape. It is split out so the
// benchmarks can sign the same template with other key types.
func leafTemplate(host string, serial *big.Int, now time.Time, ski []byte) *x509.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-backdate),
		NotAfter:     now.Add(-backdate).Add(LeafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		// serverAuth: this certificate may identify a TLS server, nothing else.
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, // CA:false
		SubjectKeyId:          ski,
		// AuthorityKeyId is copied from the parent's SubjectKeyId by
		// x509.CreateCertificate.
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	return tmpl
}
