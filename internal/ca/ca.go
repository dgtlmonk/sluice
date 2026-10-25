// Package ca is Sluice's local certificate authority (SPEC.md, Proxy engine ->
// HTTPS -> Root CA).
//
// To read HTTPS traffic, the proxy terminates TLS itself and shows the client
// a certificate for the requested host. The client only accepts that
// certificate if it chains to a root it trusts, so Sluice owns one root CA,
// which the user installs into their trust store once, by hand.
//
// What lives on disk (per-user app data folder):
//
//	ca.pem       the root certificate. Public; safe to share and export.
//	ca-keys.enc  the root private key AND the shared leaf private key,
//	             sealed with AES-256-GCM, mode 0600.
//
// The sealing key is derived from a 32-byte secret kept in the macOS
// Keychain; this package never touches the Keychain itself, the caller
// passes the secret in. Private keys never leave this package: no method
// returns or prints them.
package ca

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	// CertFile and KeysFile are the file names inside the CA directory.
	CertFile = "ca.pem"
	KeysFile = "ca-keys.enc"

	// SecretSize is the length of the Keychain-held secret LoadOrCreate needs.
	SecretSize = 32

	rsaBits      = 2048 // SPEC: one algorithm, one code path
	rootValidity = 10 * 365 * 24 * time.Hour
	// backdate covers clients whose clock runs a little behind ours.
	backdate = time.Hour

	// keysMagic versions the sealed file format. Bump it if the layout changes.
	keysMagic = "SLUICE-CA-KEYS-1\n"
	hkdfInfo  = "sluice ca-keys.enc v1"

	pemTypeRootKey = "SLUICE ROOT PRIVATE KEY"
	pemTypeLeafKey = "SLUICE LEAF PRIVATE KEY"
)

// ErrKeysMissing means ca.pem exists but its sealed keys do not. Sluice
// refuses to quietly mint a new root then: the old one may already be
// trusted, and a silent swap would surface as unexplained TLS errors.
var ErrKeysMissing = errors.New("ca: ca.pem exists but ca-keys.enc is missing; delete ca.pem to create a new CA (and remove the old one from Keychain Access)")

// Authority holds the root CA and the shared leaf key, in memory only.
type Authority struct {
	root    *x509.Certificate
	rootKey *rsa.PrivateKey
	// leafKey is one key pair shared by every minted leaf. Generating a
	// 2048-bit RSA key takes tens of milliseconds; doing it per host would
	// stall a page that opens many hosts. Only the certificate is per host.
	leafKey *rsa.PrivateKey
}

// LoadOrCreate opens the CA stored in dir, or creates one there on first run.
// secret is the 32-byte Keychain-held secret that seals the private keys.
func LoadOrCreate(dir string, secret []byte) (*Authority, error) {
	if len(secret) != SecretSize {
		return nil, fmt.Errorf("ca: secret must be %d bytes, got %d", SecretSize, len(secret))
	}
	certPath := filepath.Join(dir, CertFile)
	keysPath := filepath.Join(dir, KeysFile)

	certPEM, err := os.ReadFile(certPath) //nolint:gosec // G304: path is our own app data dir
	switch {
	case errors.Is(err, os.ErrNotExist):
		// ca.pem is written last, so its absence means no CA was ever
		// finished (a leftover keys file from a crash is overwritten).
		return create(dir, secret)
	case err != nil:
		return nil, fmt.Errorf("ca: read %s: %w", CertFile, err)
	}

	sealed, err := os.ReadFile(keysPath) //nolint:gosec // G304: see above
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrKeysMissing
	}
	if err != nil {
		return nil, fmt.Errorf("ca: read %s: %w", KeysFile, err)
	}
	return load(certPEM, sealed, secret)
}

func create(dir string, secret []byte) (*Authority, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("ca: create dir: %w", err)
	}
	a, err := generate(time.Now())
	if err != nil {
		return nil, err
	}
	sealed, err := seal(a, secret)
	if err != nil {
		return nil, err
	}
	// Keys first, certificate last: ca.pem is the "CA is complete" marker.
	if err := writeAtomic(filepath.Join(dir, KeysFile), sealed, 0o600); err != nil {
		return nil, err
	}
	if err := writeAtomic(filepath.Join(dir, CertFile), a.CertPEM(), 0o644); err != nil {
		return nil, err
	}
	return a, nil
}

// generate makes a fresh root and leaf key. now is a parameter so tests can
// pin validity dates.
func generate(now time.Time) (*Authority, error) {
	rootKey, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, fmt.Errorf("ca: generate root key: %w", err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, fmt.Errorf("ca: generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	// A short random suffix makes each install's CA name unique, so a user
	// who reinstalls can tell old and new apart in Keychain Access.
	tag := make([]byte, 4)
	if _, err := rand.Read(tag); err != nil {
		return nil, fmt.Errorf("ca: random name: %w", err)
	}
	name := pkix.Name{
		CommonName:   fmt.Sprintf("Sluice Local CA %X", tag),
		Organization: []string{"Sluice (local interception, do not share)"},
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      name,
		NotBefore:    now.Add(-backdate),
		NotAfter:     now.Add(rootValidity),
		// BasicConstraints CA:true is what makes this a CA. MaxPathLen 0 says
		// it may sign leaf certificates only, never another CA: a stolen key
		// cannot be used to create intermediates under it.
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		SubjectKeyId:          keyID(&rootKey.PublicKey),
	}
	// Self-signed: the template is both subject and issuer.
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("ca: sign root: %w", err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("ca: parse root: %w", err)
	}
	return &Authority{root: root, rootKey: rootKey, leafKey: leafKey}, nil
}

func load(certPEM, sealed, secret []byte) (*Authority, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("ca: %s is not a PEM certificate", CertFile)
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse %s: %w", CertFile, err)
	}
	rootKey, leafKey, err := open(sealed, secret, root.Raw)
	if err != nil {
		return nil, err
	}
	// The key must belong to the certificate; otherwise every leaf we sign
	// would fail verification in the client.
	if !rootKey.PublicKey.Equal(root.PublicKey) {
		return nil, errors.New("ca: root key does not match ca.pem")
	}
	return &Authority{root: root, rootKey: rootKey, leafKey: leafKey}, nil
}

// seal encrypts both private keys. Layout: magic | nonce | GCM ciphertext.
// The additional data binds the ciphertext to this root certificate, so
// swapping in a different ca.pem is detected on open.
func seal(a *Authority, secret []byte) ([]byte, error) {
	var plain bytes.Buffer
	for _, k := range []struct {
		typ string
		key *rsa.PrivateKey
	}{{pemTypeRootKey, a.rootKey}, {pemTypeLeafKey, a.leafKey}} {
		der, err := x509.MarshalPKCS8PrivateKey(k.key)
		if err != nil {
			return nil, fmt.Errorf("ca: marshal key: %w", err)
		}
		if err := pem.Encode(&plain, &pem.Block{Type: k.typ, Bytes: der}); err != nil {
			return nil, fmt.Errorf("ca: encode key: %w", err)
		}
		clear(der)
	}
	defer clear(plain.Bytes())

	aead, err := newAEAD(secret)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("ca: nonce: %w", err)
	}
	out := append([]byte(keysMagic), nonce...)
	return aead.Seal(out, nonce, plain.Bytes(), aad(a.root.Raw)), nil
}

func open(sealed, secret, rootDER []byte) (rootKey, leafKey *rsa.PrivateKey, err error) {
	rest, ok := bytes.CutPrefix(sealed, []byte(keysMagic))
	if !ok {
		return nil, nil, fmt.Errorf("ca: %s has an unknown format", KeysFile)
	}
	aead, err := newAEAD(secret)
	if err != nil {
		return nil, nil, err
	}
	if len(rest) < aead.NonceSize() {
		return nil, nil, fmt.Errorf("ca: %s is truncated", KeysFile)
	}
	nonce, ct := rest[:aead.NonceSize()], rest[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, ct, aad(rootDER))
	if err != nil {
		// GCM cannot tell "wrong secret" from "tampered file" from "keys of
		// another ca.pem"; all three mean we must not use it.
		return nil, nil, fmt.Errorf("ca: cannot decrypt %s (wrong Keychain secret, or the file does not belong to this ca.pem)", KeysFile)
	}
	defer clear(plain)

	keys := map[string]*rsa.PrivateKey{}
	for rest := plain; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		clear(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("ca: parse sealed key: %w", err)
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, errors.New("ca: sealed key is not RSA")
		}
		keys[block.Type] = rk
	}
	rootKey, leafKey = keys[pemTypeRootKey], keys[pemTypeLeafKey]
	if rootKey == nil || leafKey == nil {
		return nil, nil, fmt.Errorf("ca: %s is missing a key", KeysFile)
	}
	return rootKey, leafKey, nil
}

// newAEAD derives the AES-256 key from the Keychain secret with HKDF. The
// secret is already 32 random bytes, so no slow password hash is needed;
// HKDF just gives this file its own key, separate from any other use of
// the same secret.
func newAEAD(secret []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, secret, nil, hkdfInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("ca: derive key: %w", err)
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("ca: cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

func aad(rootDER []byte) []byte {
	sum := sha256.Sum256(rootDER)
	return append([]byte(keysMagic), sum[:]...)
}

// Certificate returns the root certificate (public).
func (a *Authority) Certificate() *x509.Certificate { return a.root }

// CertPEM returns the root certificate as PEM. Certificate only, never a key.
func (a *Authority) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.root.Raw})
}

// Fingerprint is the SHA-256 of the root certificate's DER bytes, the value
// Keychain Access shows, so the user can match what they installed.
func (a *Authority) Fingerprint() [32]byte { return sha256.Sum256(a.root.Raw) }

func randomSerial() (*big.Int, error) {
	// 128 random bits, well above the 64 bits CA/Browser rules ask for.
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("ca: serial: %w", err)
	}
	return n.Add(n, big.NewInt(1)), nil // never zero
}

// keyID is the Subject Key Identifier: a short hash of the public key that
// lets a verifier match a leaf's Authority Key Identifier to its issuer.
// RFC 7093 method 1: leftmost 160 bits of SHA-256 over the key bits.
func keyID(pub *rsa.PublicKey) []byte {
	sum := sha256.Sum256(x509.MarshalPKCS1PublicKey(pub))
	return sum[:20]
}

// writeAtomic writes to a temp file in the same directory, then renames it
// over the target, so a crash never leaves a half-written file.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := writeTemp(path, data, mode); err != nil {
		return fmt.Errorf("ca: write %s: %w", filepath.Base(path), err)
	}
	return nil
}

func writeTemp(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op after a successful rename
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
