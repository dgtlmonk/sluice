// Package loadgen sends a fixed mix of HTTP/1.1 requests through a forward
// proxy to an internal/testorigin server and measures latency. It is test
// and tooling code, not the proxy path, so it uses net/http as a CLIENT:
// the point is to load the hand-written proxy, not to test a client.
//
// The mix (by request index, repeating every 20) covers every framing the
// proxy must carry under load:
//
//	1 in 20  GET  /sse                   text/event-stream, ~150 ms long
//	4 in 20  POST /v1/chat/completions   JSON chat body, Content-Length
//	2 in 20  POST /v1/chat/completions   JSON chat body, chunked request
//	5 in 20  GET  /chunked               chunked response
//	4 in 20  GET  /content-length        Content-Length response
//	4 in 20  GET  /keep-alive            small Content-Length response
//
// Workers share one Transport with keep-alive on, so most requests reuse a
// proxy connection (the proxy also keeps its own origin pool).
package loadgen

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dgtlmonk/sluice/internal/testorigin"
)

// ChatBody is the request body of the LLM-shaped POSTs: model + messages[],
// which the passive detector flags as "path" (the path matches first).
const ChatBody = `{"model":"load-test","messages":[{"role":"user","content":"hello from loadgen"}]}`

// Config describes one run.
type Config struct {
	Proxy       string        // proxy host:port
	Origin      string        // testorigin host:port
	N           int           // total requests
	Concurrency int           // parallel clients
	Timeout     time.Duration // per request; 0 means 10 s
}

// Result is what a run measured.
type Result struct {
	OK        int
	Failed    int
	FirstErr  error
	Wall      time.Duration
	Latencies []time.Duration // sorted ascending, one per OK request
	ByKind    map[string]int  // OK requests per mix kind
}

// RPS is completed requests per second of wall time.
func (r Result) RPS() float64 {
	if r.Wall <= 0 {
		return 0
	}
	return float64(r.OK) / r.Wall.Seconds()
}

// Percentile returns the p-th (0..100) latency, nearest-rank.
func (r Result) Percentile(p float64) time.Duration {
	if len(r.Latencies) == 0 {
		return 0
	}
	i := int(float64(len(r.Latencies))*p/100+0.5) - 1
	i = max(0, min(i, len(r.Latencies)-1))
	return r.Latencies[i]
}

func (r Result) String() string {
	return fmt.Sprintf("ok=%d failed=%d wall=%s rps=%.0f p50=%s p99=%s max=%s",
		r.OK, r.Failed, r.Wall.Round(time.Millisecond), r.RPS(),
		r.Percentile(50).Round(10*time.Microsecond), r.Percentile(99).Round(10*time.Microsecond),
		r.Percentile(100).Round(10*time.Microsecond))
}

type kind struct {
	name, method, path string
	chunked            bool   // send the request body chunked
	want               string // expected decoded response body
}

// mix is indexed by i % len(mix).
var mix = func() []kind {
	sse := kind{"sse", "GET", testorigin.PathSSE, false, testorigin.SSEBody()}
	chatCL := kind{"chat-cl", "POST", testorigin.PathChat, false, testorigin.ChatReply}
	chatTE := kind{"chat-chunked", "POST", testorigin.PathChat, true, testorigin.ChatReply}
	chunked := kind{"chunked", "GET", testorigin.PathChunked, false, testorigin.ChunkedBody()}
	cl := kind{"content-length", "GET", testorigin.PathContentLength, false, testorigin.ContentLengthBody}
	ka := kind{"keep-alive", "GET", testorigin.PathKeepAlive, false, testorigin.KeepAliveBody}
	return []kind{
		sse, chatCL, chunked, cl, ka,
		chatCL, chunked, cl, ka, chatTE,
		chatCL, chunked, cl, ka, chunked,
		chatCL, chunked, cl, ka, chatTE,
	}
}()

// KindOf names the mix kind of request i (for asserting per-kind counts).
func KindOf(i int) string { return mix[i%len(mix)].name }

// chunkedReader hides its length from net/http, which then sends the body
// with Transfer-Encoding: chunked.
type chunkedReader struct{ r io.Reader }

func (c chunkedReader) Read(p []byte) (int, error) { return c.r.Read(p) }

// Run sends cfg.N requests. It stops early only when ctx is cancelled.
func Run(ctx context.Context, cfg Config) (Result, error) {
	if cfg.N <= 0 || cfg.Concurrency <= 0 || cfg.Proxy == "" || cfg.Origin == "" {
		return Result{}, errors.New("loadgen: proxy, origin, n > 0 and concurrency > 0 are required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	pu, err := url.Parse("http://" + cfg.Proxy)
	if err != nil {
		return Result{}, fmt.Errorf("loadgen: proxy address: %w", err)
	}
	tr := &http.Transport{
		Proxy:               http.ProxyURL(pu),
		MaxIdleConns:        cfg.Concurrency,
		MaxIdleConnsPerHost: cfg.Concurrency,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  true, // keep the bytes on the wire what testorigin sent
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: cfg.Timeout}

	var (
		next    atomic.Int64
		mu      sync.Mutex
		res     = Result{ByKind: map[string]int{}}
		lat     = make([]time.Duration, 0, cfg.N)
		wg      sync.WaitGroup
		base    = "http://" + cfg.Origin
		started = time.Now()
	)
	for range cfg.Concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= cfg.N || ctx.Err() != nil {
					return
				}
				k := mix[i%len(mix)]
				t0 := time.Now()
				err := do(ctx, client, base, k)
				d := time.Since(t0)
				mu.Lock()
				if err != nil {
					res.Failed++
					if res.FirstErr == nil {
						res.FirstErr = fmt.Errorf("request %d (%s): %w", i, k.name, err)
					}
				} else {
					res.OK++
					res.ByKind[k.name]++
					lat = append(lat, d)
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	res.Wall = time.Since(started)
	slices.Sort(lat)
	res.Latencies = lat
	return res, nil
}

func do(ctx context.Context, client *http.Client, base string, k kind) error {
	var body io.Reader
	if k.method == "POST" {
		body = strings.NewReader(ChatBody)
		if k.chunked {
			body = chunkedReader{body}
		}
	}
	req, err := http.NewRequestWithContext(ctx, k.method, base+k.path, body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	got, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	if string(got) != k.want {
		return fmt.Errorf("body mismatch: got %d bytes", len(got))
	}
	return nil
}
