package main

import (
	"bytes"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dgtlmonk/sluice/internal/platform"
)

type fakeTrust struct {
	installed []*x509.Certificate
	report    platform.TrustReport
	probeHost string
	probe     *x509.Certificate
}

func (f *fakeTrust) InstallRoot(root *x509.Certificate) error {
	f.installed = append(f.installed, root)
	return nil
}

func (f *fakeTrust) Check(_, probe *x509.Certificate, host string) (platform.TrustReport, error) {
	f.probe, f.probeHost = probe, host
	return f.report, nil
}

func fixedSecret(string) ([]byte, error) { return bytes.Repeat([]byte{7}, 32), nil }

func TestCAServiceFlow(t *testing.T) {
	ft := &fakeTrust{report: platform.TrustReport{Installed: true, Trusted: true}}
	s := newCAService(ft)
	dir := t.TempDir()
	s.load(dir, fixedSecret)

	info := s.info()
	if !info.Ready || info.Error != "" || !strings.HasPrefix(info.Subject, "Sluice Local CA") ||
		len(info.Fingerprint) != 32*3-1 || info.Dir != dir {
		t.Fatalf("info %+v", info)
	}

	rep, err := s.check()
	if err != nil || !rep.Trusted {
		t.Fatalf("check %+v %v", rep, err)
	}
	if ft.probeHost != trustProbeHost || ft.probe == nil || ft.probe.IsCA {
		t.Fatal("check did not verify a minted probe leaf")
	}

	if err := s.install(); err != nil || len(ft.installed) != 1 || !ft.installed[0].IsCA {
		t.Fatalf("install: %v", err)
	}

	out := filepath.Join(t.TempDir(), "ca.pem")
	if err := s.export(out); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out) //nolint:gosec // G304: temp dir
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(b, []byte("-----BEGIN CERTIFICATE-----")) || bytes.Contains(b, []byte("PRIVATE")) {
		t.Fatal("export is not the certificate alone")
	}

	// Same folder + secret on the next launch: the same CA.
	s2 := newCAService(ft)
	s2.load(dir, fixedSecret)
	if s2.info().Fingerprint != info.Fingerprint {
		t.Fatal("CA changed across launches")
	}
}

func TestCAServiceLoadFailure(t *testing.T) {
	ft := &fakeTrust{}
	s := newCAService(ft)
	s.load(t.TempDir(), func(string) ([]byte, error) { return nil, errors.New("keychain locked") })
	if info := s.info(); info.Ready || !strings.Contains(info.Error, "keychain locked") {
		t.Fatalf("info %+v", info)
	}
	if _, err := s.check(); err == nil {
		t.Fatal("check without a CA")
	}
	if s.install() == nil || len(ft.installed) != 0 {
		t.Fatal("install without a CA")
	}
}
