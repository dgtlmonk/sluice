package ca

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testSecret(t *testing.T) []byte {
	t.Helper()
	s := make([]byte, SecretSize)
	if _, err := rand.Read(s); err != nil {
		t.Fatal(err)
	}
	return s
}

// Test files live under t.TempDir(); gosec cannot see that.
func readTestFile(p string) ([]byte, error) { return os.ReadFile(p) } //nolint:gosec // G304: temp dir

func writeTestFile(p string, b []byte) error { return os.WriteFile(p, b, 0o600) } //nolint:gosec // G703: temp dir

func TestCreateThenReload(t *testing.T) {
	dir := t.TempDir()
	secret := testSecret(t)

	first, err := LoadOrCreate(dir, secret)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	again, err := LoadOrCreate(dir, secret)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !bytes.Equal(first.root.Raw, again.root.Raw) {
		t.Fatal("reload produced a different root")
	}
	if !first.leafKey.Equal(again.leafKey) {
		t.Fatal("reload produced a different shared leaf key")
	}

	for name, want := range map[string]os.FileMode{CertFile: 0o644, KeysFile: 0o600} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s mode %o, want %o", name, fi.Mode().Perm(), want)
		}
	}
}

func TestRootShape(t *testing.T) {
	now := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	a, err := generate(now)
	if err != nil {
		t.Fatal(err)
	}
	c := a.root
	if !c.IsCA || !c.BasicConstraintsValid || c.MaxPathLen != 0 || !c.MaxPathLenZero {
		t.Error("root must be CA:true with pathlen 0")
	}
	if c.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("root lacks keyCertSign")
	}
	if c.PublicKeyAlgorithm != x509.RSA || a.rootKey.N.BitLen() != 2048 {
		t.Error("root must be RSA 2048")
	}
	if got := c.NotAfter.Sub(now); got != rootValidity {
		t.Errorf("validity %v, want %v", got, rootValidity)
	}
	if len(c.SubjectKeyId) == 0 {
		t.Error("root has no SKI")
	}
	if err := c.CheckSignatureFrom(c); err != nil {
		t.Errorf("root is not self-signed: %v", err)
	}
}

// TestNoPrivateKeyInPlaintext: neither file on disk may contain key
// material in the clear.
func TestNoPrivateKeyInPlaintext(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadOrCreate(dir, testSecret(t))
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(a.rootKey)
	for _, name := range []string{CertFile, KeysFile} {
		b, err := readTestFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte("PRIVATE KEY")) || bytes.Contains(b, der[len(der)-64:]) {
			t.Errorf("%s holds plaintext key material", name)
		}
	}
	if bytes.Contains(a.CertPEM(), []byte("PRIVATE")) {
		t.Error("CertPEM leaks a key")
	}
}

func TestWrongSecretRejected(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreate(dir, testSecret(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(dir, testSecret(t)); err == nil {
		t.Fatal("opened with a different secret")
	}
}

// TestKeysBoundToCert: keys sealed for one root must not open next to
// another root's ca.pem (GCM additional data is the root's hash).
func TestKeysBoundToCert(t *testing.T) {
	secret := testSecret(t)
	d1, d2 := t.TempDir(), t.TempDir()
	if _, err := LoadOrCreate(d1, secret); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(d2, secret); err != nil {
		t.Fatal(err)
	}
	other, err := readTestFile(filepath.Join(d2, CertFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeTestFile(filepath.Join(d1, CertFile), other); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(d1, secret); err == nil {
		t.Fatal("keys opened against a different ca.pem")
	}
}

func TestTamperedKeysRejected(t *testing.T) {
	dir := t.TempDir()
	secret := testSecret(t)
	if _, err := LoadOrCreate(dir, secret); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, KeysFile)
	b, _ := readTestFile(p)
	b[len(b)-1] ^= 1
	if err := writeTestFile(p, b); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(dir, secret); err == nil {
		t.Fatal("tampered keys accepted")
	}
}

func TestMissingKeysIsAnErrorNotARegenerate(t *testing.T) {
	dir := t.TempDir()
	secret := testSecret(t)
	if _, err := LoadOrCreate(dir, secret); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, KeysFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(dir, secret); !errors.Is(err, ErrKeysMissing) {
		t.Fatalf("got %v, want ErrKeysMissing", err)
	}
}

// TestLeftoverKeysWithoutCertRecreates: a crash after writing the keys but
// before ca.pem leaves no usable CA, so the next run starts over.
func TestLeftoverKeysWithoutCertRecreates(t *testing.T) {
	dir := t.TempDir()
	secret := testSecret(t)
	if _, err := LoadOrCreate(dir, secret); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, CertFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(dir, secret); err != nil {
		t.Fatalf("recreate: %v", err)
	}
}

func TestBadSecretLength(t *testing.T) {
	if _, err := LoadOrCreate(t.TempDir(), make([]byte, 16)); err == nil {
		t.Fatal("accepted a 16-byte secret")
	}
}

func TestMintLeafVerifiesAgainstRoot(t *testing.T) {
	a, err := LoadOrCreate(t.TempDir(), testSecret(t))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(a.Certificate())

	for _, host := range []string{"example.test", "Sub.Example.Test.", "127.0.0.1", "::1"} {
		c, err := a.MintLeaf(host)
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		leaf := c.Leaf
		want := strings.TrimSuffix(strings.ToLower(host), ".")
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: want, Roots: roots}); err != nil {
			t.Errorf("%s: verify: %v", host, err)
		}
		if leaf.IsCA {
			t.Errorf("%s: leaf is a CA", host)
		}
		if got := leaf.NotAfter.Sub(leaf.NotBefore); got != LeafValidity || got > 398*24*time.Hour {
			t.Errorf("%s: validity %v", host, got)
		}
		if !bytes.Equal(leaf.AuthorityKeyId, a.root.SubjectKeyId) || len(leaf.SubjectKeyId) == 0 {
			t.Errorf("%s: SKI/AKI not set", host)
		}
		if ip := net.ParseIP(want); ip != nil && len(leaf.IPAddresses) != 1 {
			t.Errorf("%s: IP SAN missing", host)
		}
		if len(c.Certificate) != 2 || !bytes.Equal(c.Certificate[1], a.root.Raw) {
			t.Errorf("%s: chain must be [leaf, root]", host)
		}
	}

	x, _ := a.MintLeaf("a.test")
	y, _ := a.MintLeaf("a.test")
	if x.Leaf.SerialNumber.Cmp(y.Leaf.SerialNumber) == 0 {
		t.Error("serials repeat")
	}
	if !x.Leaf.PublicKey.(*rsa.PublicKey).Equal(y.Leaf.PublicKey) {
		t.Error("leaves do not share the leaf key")
	}
	if _, err := a.MintLeaf(""); err == nil {
		t.Error("empty host accepted")
	}
}

// TestLeafServesTLS: a minted leaf completes a real TLS handshake for a
// client that trusts only our root.
func TestLeafServesTLS(t *testing.T) {
	a, err := LoadOrCreate(t.TempDir(), testSecret(t))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := a.MintLeaf("origin.test")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(a.Certificate())

	cConn, sConn := net.Pipe()
	defer func() { _ = cConn.Close() }()
	defer func() { _ = sConn.Close() }()
	errc := make(chan error, 1)
	go func() {
		srv := tls.Server(sConn, &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12})
		errc <- srv.Handshake()
	}()
	cli := tls.Client(cConn, &tls.Config{ServerName: "origin.test", RootCAs: roots, MinVersion: tls.VersionTLS12})
	if err := cli.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
}
