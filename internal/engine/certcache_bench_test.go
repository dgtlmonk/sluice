package engine

import "testing"

// BenchmarkCertCacheHit measures the path every handshake after the first
// one per host takes: lowercase the name, take the mutex, map lookup. The
// leaf is minted once before the timer starts.
func BenchmarkCertCacheHit(b *testing.B) {
	a, _ := testCA(b)
	c := newCertCache(a)
	if _, err := c.get("cached.example.test"); err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if _, err := c.get("cached.example.test"); err != nil {
			b.Fatal(err)
		}
	}
}
