package synth

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestExchangeIsDeterministicPerID(t *testing.T) {
	g := New(1)
	at := time.UnixMilli(1_700_000_000_000)
	for id := int64(0); id < 100; id++ {
		if a, b := g.Exchange(id, at), g.Exchange(id, at); a != b {
			t.Fatalf("id %d: got %+v then %+v", id, a, b)
		}
	}
}

func TestSeedsDiffer(t *testing.T) {
	at := time.Now()
	same := 0
	for id := int64(0); id < 200; id++ {
		if New(1).Exchange(id, at) == New(2).Exchange(id, at) {
			same++
		}
	}
	if same == 200 {
		t.Fatal("different seeds produced identical streams")
	}
}

func TestExchangeFieldsAreSane(t *testing.T) {
	g := New(7)
	llm := 0
	for id := int64(0); id < 5_000; id++ {
		x := g.Exchange(id, time.Now())
		if x.ID != id || x.Host == "" || !strings.HasPrefix(x.Path, "/") || x.ReqSize <= 0 {
			t.Fatalf("bad exchange %+v", x)
		}
		if _, ok := reasons[x.Status]; !ok {
			t.Fatalf("status %d has no reason phrase", x.Status)
		}
		if x.IsLLM {
			llm++
			isKnownLLM := x.Host == "api.openai.com" || x.Host == "api.anthropic.com" ||
				x.Host == "generativelanguage.googleapis.com" || (x.Host == "localhost" && x.Port == 11434)
			if !isKnownLLM {
				t.Fatalf("unexpected LLM host %s:%d", x.Host, x.Port)
			}
		}
	}
	if llm == 0 || llm > 2_500 {
		t.Fatalf("LLM share looks wrong: %d of 5000", llm)
	}
}

func TestDetailMatchesExchange(t *testing.T) {
	g := New(3)
	for id := int64(0); id < 50; id++ {
		x := g.Exchange(id, time.Now())
		d := g.Detail(id)
		if !strings.HasPrefix(d.Request, x.Method+" "+x.Path+" HTTP/1.1\r\n") {
			t.Fatalf("id %d: request line mismatch: %q", id, d.Request)
		}
		if !strings.Contains(d.Request, "\r\nHost: "+x.Host) {
			t.Fatalf("id %d: host header missing: %q", id, d.Request)
		}
		if !strings.HasPrefix(d.Response, "HTTP/1.1 ") {
			t.Fatalf("id %d: bad status line: %q", id, d.Response)
		}
	}
}

// Cancelling mid-burst must stop Produce before the next publish, even when a
// single tick owes a large backlog.
func TestProduceStopsMidBurstOnCancel(t *testing.T) {
	g := New(1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var id, published int64
	g.Produce(ctx, 100_000, func() int64 { id++; return id }, func(Exchange) bool {
		published++
		cancel() // first tick owes ~1000 events at this rate
		return true
	})
	if published != 1 {
		t.Fatalf("published %d events after cancel, want 1", published)
	}
}
