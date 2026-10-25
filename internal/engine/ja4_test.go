package engine

import "testing"

// The worked example from FoxIO's JA4 technical details (a Chrome
// ClientHello): the cipher and extension lists below are the ones the spec
// prints, and t13d1516h2_8daaf6152771_e5627efa2ab1 is its published result.
// https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
// The hello here is crafted from those lists, with GREASE values and a
// shuffled extension order added, as Chrome sends them; neither may change
// the fingerprint.
func TestJA4FoxIOChromeVector(t *testing.T) {
	const want = "t13d1516h2_8daaf6152771_e5627efa2ab1"
	ext := func(typ uint16) rawExt { return rawExt{typ: typ, data: []byte{0}} } // content irrelevant to JA4
	h := helloSpec{
		legacy: 0x0303,
		ciphers: []uint16{0x2a2a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
			0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035},
		exts: []rawExt{
			ext(0x3a3a), // GREASE
			ext(0x0023), ext(0x4469), sniExt("example.com"), ext(0x0012), ext(0x0017),
			versionsExt(0x7a7a, 0x0304, 0x0303),
			sigAlgsExt(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601),
			ext(0x000b), ext(0xff01), alpnExt("h2", "http/1.1"), ext(0x0005), ext(0x002d),
			ext(0x000a), ext(0x0033), ext(0x001b), ext(0x0015),
			ext(0x1a1a), // GREASE again, last as Chrome does
		},
	}
	_, ch, err := readHello(h.wire())
	if err != nil {
		t.Fatal(err)
	}
	if got := ja4(ch); got != want {
		t.Fatalf("JA4 = %s, want %s", got, want)
	}
}

// The spec's second c-part vector: the same extensions, no signature
// algorithms, so no underscore before hashing.
func TestJA4FoxIONoSigAlgsVector(t *testing.T) {
	h := clientHello{
		LegacyVersion: 0x0303,
		CipherSuites:  []uint16{0x1301},
		Extensions:    []uint16{0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015},
	}
	if got := ja4(&h); got[len(got)-12:] != "6d807ffa2a79" {
		t.Fatalf("JA4 = %s, want c = 6d807ffa2a79", got)
	}
}

func TestJA4Parts(t *testing.T) {
	cases := []struct {
		name string
		h    clientHello
		want string
	}{
		{
			// No SNI (an IP target), no ALPN, TLS 1.2 only via legacy_version.
			name: "ip, no alpn, tls12",
			h:    clientHello{LegacyVersion: 0x0303, CipherSuites: []uint16{0xc02f}, Extensions: []uint16{0x000a}},
			want: "t12i0101" + "00_",
		},
		{
			name: "no extensions at all",
			h:    clientHello{LegacyVersion: 0x0301, CipherSuites: []uint16{0x002f}},
			want: "t10i010000_",
		},
	}
	for _, c := range cases {
		got := ja4(&c.h)
		if got[:len(c.want)] != c.want {
			t.Errorf("%s: JA4 = %s, want prefix %s", c.name, got, c.want)
		}
	}
	// Only SNI and ALPN: c has no extensions left, so it is all zeros.
	only := clientHello{LegacyVersion: 0x0303, CipherSuites: []uint16{0x1301}, Extensions: []uint16{extServerName, extALPN}, ALPN: []string{"http/1.1"}}
	if got := ja4(&only); got[len(got)-12:] != "000000000000" || got[:10] != "t12d0102h1" {
		t.Errorf("only SNI+ALPN: %s", got)
	}
}

func TestJA4ALPNAndVersion(t *testing.T) {
	// The non-alphanumeric cases are the examples printed in the JA4 spec.
	alpn := map[string]string{
		"h2": "h2", "http/1.1": "h1", "h": "hh",
		"\xab": "ab", "\x20": "20", "\xab\xcd": "ad", "\x20\x61": "21", "\x30\xab": "3b",
		"\x61\x20": "60", "\x30\x31\xab\xcd": "3d", "\x30\xab\xcd\x31": "01",
	}
	for in, want := range alpn {
		if got := ja4ALPN([]string{in}); got != want {
			t.Errorf("ALPN %q: %s, want %s", in, got, want)
		}
	}
	versions := map[uint16]string{0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2", 0xfefd: "d2", 0x9999: "00"}
	for v, want := range versions {
		if got := ja4Version(&clientHello{LegacyVersion: v}); got != want {
			t.Errorf("version %#04x: %s, want %s", v, got, want)
		}
	}
	// supported_versions wins over legacy_version; GREASE is ignored.
	if got := ja4Version(&clientHello{LegacyVersion: 0x0303, SupportedVersions: []uint16{0xfafa, 0x0303, 0x0304}}); got != "13" {
		t.Errorf("supported_versions: %s", got)
	}
}

func TestIsGREASE(t *testing.T) {
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0xaaaa, 0xfafa} {
		if !isGREASE(v) {
			t.Errorf("%#04x not GREASE", v)
		}
	}
	for _, v := range []uint16{0x0a1a, 0x1301, 0x0000, 0x0b0b} {
		if isGREASE(v) {
			t.Errorf("%#04x GREASE", v)
		}
	}
}
