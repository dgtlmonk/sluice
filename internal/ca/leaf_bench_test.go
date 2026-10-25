package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"testing"
	"time"
)

// These benchmarks answer one question: is sharing one leaf key worth it?
// Minting a leaf = (maybe) make a key pair + one RSA signature by the root.
// The shared-key case pays only the signature; the fresh-key cases pay key
// generation too. Run:
//
//	go test -run '^$' -bench Mint -benchmem -count=5 ./internal/ca/

func benchAuthority(b *testing.B) *Authority {
	b.Helper()
	a, err := generate(time.Now())
	if err != nil {
		b.Fatal(err)
	}
	return a
}

// BenchmarkMintLeafSharedKey is what Sluice does: the leaf key already
// exists (made once, outside the timed loop); each host costs one signature.
func BenchmarkMintLeafSharedKey(b *testing.B) {
	a := benchAuthority(b)
	i := 0
	for b.Loop() {
		if _, err := a.MintLeaf(fmt.Sprintf("h%d.example.test", i)); err != nil {
			b.Fatal(err)
		}
		i++
	}
}

// BenchmarkMintLeafFreshRSA2048 makes a new RSA 2048 leaf key per host,
// inside the timed loop, then signs the same certificate.
func BenchmarkMintLeafFreshRSA2048(b *testing.B) {
	a := benchAuthority(b)
	i := 0
	for b.Loop() {
		k, err := rsa.GenerateKey(rand.Reader, rsaBits)
		if err != nil {
			b.Fatal(err)
		}
		mintWithKey(b, a, fmt.Sprintf("h%d.example.test", i), k.Public(), keyID(&k.PublicKey))
		i++
	}
}

// BenchmarkMintLeafFreshECDSAP256 is the cheaper alternative: a P-256 key is
// a random scalar plus one point multiplication, far faster than finding
// two 1024-bit primes. The root still signs with RSA.
func BenchmarkMintLeafFreshECDSAP256(b *testing.B) {
	a := benchAuthority(b)
	i := 0
	for b.Loop() {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		der, err := x509.MarshalPKIXPublicKey(k.Public())
		if err != nil {
			b.Fatal(err)
		}
		ski := sha256.Sum256(der)
		mintWithKey(b, a, fmt.Sprintf("h%d.example.test", i), k.Public(), ski[:20])
		i++
	}
}

// mintWithKey mirrors mintLeaf (template, root signature, parse) for a
// leaf public key other than the shared one.
func mintWithKey(b *testing.B, a *Authority, host string, pub crypto.PublicKey, ski []byte) {
	b.Helper()
	serial, err := randomSerial()
	if err != nil {
		b.Fatal(err)
	}
	tmpl := leafTemplate(host, serial, time.Now(), ski)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.root, pub, a.rootKey)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := x509.ParseCertificate(der); err != nil {
		b.Fatal(err)
	}
}
