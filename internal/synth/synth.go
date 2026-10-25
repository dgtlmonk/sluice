// Package synth generates fake HTTP exchanges for UI load testing (M0 go/no-go).
//
// Every field except StartedAt is a pure function of (seed, id), so the detail
// pane can regenerate an exchange's raw text from its id instead of the rows
// carrying that text across the bridge.
package synth

import (
	"context"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"
)

// Exchange is one row of the History grid.
type Exchange struct {
	ID         int64  `json:"id"`
	StartedAt  int64  `json:"startedAt"` // unix ms
	Method     string `json:"method"`
	Scheme     string `json:"scheme"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Path       string `json:"path"`
	Status     int    `json:"status"`
	ReqSize    int    `json:"reqSize"`
	RespSize   int    `json:"respSize"`
	MIME       string `json:"mime"`
	DurationMs int    `json:"durationMs"`
	IsLLM      bool   `json:"isLLM"`
	LLMReason  string `json:"llmReason"` // detection rules that matched, e.g. "path,sse"
}

// Detail is the raw request and response text shown when a row is selected.
type Detail struct {
	ID       int64  `json:"id"`
	Request  string `json:"request"`
	Response string `json:"response"`
}

type endpoint struct {
	scheme string
	host   string
	port   int
	paths  []string
	llm    bool
	weight int
}

// Weights favour ordinary web traffic; roughly one exchange in eight is LLM traffic.
var endpoints = []endpoint{
	{"https", "www.example.com", 443, []string{"/", "/about", "/static/app.js", "/static/site.css", "/img/hero.webp", "/favicon.ico"}, false, 20},
	{"https", "api.example.com", 443, []string{"/v2/users", "/v2/users/42", "/v2/orders", "/v2/orders/9001/items", "/v2/session"}, false, 18},
	{"https", "cdn.jsdelivr.net", 443, []string{"/npm/react@18.3.1/umd/react.production.min.js", "/npm/lodash@4.17.21/lodash.min.js"}, false, 10},
	{"https", "fonts.gstatic.com", 443, []string{"/s/inter/v13/UcC73FwrK3iLTeHuS_fvQtMwCp50KnMa1ZL7.woff2"}, false, 6},
	{"https", "telemetry.example.net", 443, []string{"/collect", "/v1/events", "/beacon"}, false, 12},
	{"http", "localhost", 5000, []string{"/", "/health", "/api/items", "/api/items/7", "/sse/stream"}, false, 10},
	{"https", "api.openai.com", 443, []string{"/v1/chat/completions", "/v1/responses", "/v1/embeddings"}, true, 6},
	{"https", "api.anthropic.com", 443, []string{"/v1/messages"}, true, 4},
	{"http", "localhost", 11434, []string{"/api/chat", "/api/generate", "/api/tags"}, true, 3},
	{"https", "generativelanguage.googleapis.com", 443, []string{"/v1beta/models/gemini-2.0-flash:generateContent"}, true, 2},
}

var totalWeight = func() int {
	sum := 0
	for _, e := range endpoints {
		sum += e.weight
	}
	return sum
}()

var statuses = []struct {
	code   int
	weight int
}{
	{200, 70}, {204, 4}, {301, 2}, {304, 8}, {400, 3}, {401, 3}, {403, 2}, {404, 5}, {429, 1}, {500, 1}, {502, 1},
}

var reasons = map[int]string{
	200: "OK", 204: "No Content", 301: "Moved Permanently", 304: "Not Modified",
	400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
	429: "Too Many Requests", 500: "Internal Server Error", 502: "Bad Gateway",
}

// Generator produces deterministic exchanges for a fixed seed.
type Generator struct {
	seed uint64
}

// New returns a Generator for seed.
func New(seed uint64) Generator {
	return Generator{seed: seed}
}

// rng returns a PRNG unique to (seed, id); creating a PCG is a couple of words, so per-call is fine.
func (g Generator) rng(id int64) *rand.Rand {
	return rand.New(rand.NewPCG(g.seed, uint64(id))) //nolint:gosec // fake test traffic, not security-sensitive
}

// Exchange builds exchange id, stamped with startedAt.
func (g Generator) Exchange(id int64, startedAt time.Time) Exchange {
	r := g.rng(id)
	ep := pickEndpoint(r)
	path := ep.paths[r.IntN(len(ep.paths))]
	method, mime := methodAndMIME(r, ep, path)
	status := pickStatus(r)

	reqSize := 180 + r.IntN(600)
	if method == "POST" || method == "PUT" {
		reqSize += r.IntN(8_000)
	}
	respSize := 0
	if status != 204 && status != 304 {
		respSize = 120 + r.IntN(40_000)
	}
	duration := 5 + r.IntN(400)
	if ep.llm {
		duration = 300 + r.IntN(9_000) // model latency
	}

	return Exchange{
		ID:         id,
		StartedAt:  startedAt.UnixMilli(),
		Method:     method,
		Scheme:     ep.scheme,
		Host:       ep.host,
		Port:       ep.port,
		Path:       path,
		Status:     status,
		ReqSize:    reqSize,
		RespSize:   respSize,
		MIME:       mime,
		DurationMs: duration,
		IsLLM:      ep.llm,
		LLMReason:  synthReason(ep.llm),
	}
}

// Detail regenerates the raw request/response text for exchange id.
func (g Generator) Detail(id int64) Detail {
	x := g.Exchange(id, time.Time{})
	return Detail{ID: id, Request: rawRequest(x), Response: rawResponse(x)}
}

func pickEndpoint(r *rand.Rand) endpoint {
	n := r.IntN(totalWeight)
	for _, e := range endpoints {
		if n < e.weight {
			return e
		}
		n -= e.weight
	}
	return endpoints[0]
}

func pickStatus(r *rand.Rand) int {
	n := r.IntN(100)
	for _, s := range statuses {
		if n < s.weight {
			return s.code
		}
		n -= s.weight
	}
	return 200
}

func methodAndMIME(r *rand.Rand, ep endpoint, path string) (method, mime string) {
	switch {
	case ep.llm && strings.HasSuffix(path, "/tags"):
		return "GET", "application/json"
	case ep.llm && strings.HasSuffix(path, "/embeddings"):
		return "POST", "application/json"
	case ep.llm:
		// Roughly half of LLM calls stream their answer as server-sent events.
		if r.IntN(2) == 0 {
			return "POST", "text/event-stream"
		}
		return "POST", "application/json"
	case strings.HasSuffix(path, ".js"):
		return "GET", "application/javascript"
	case strings.HasSuffix(path, ".css"):
		return "GET", "text/css"
	case strings.HasSuffix(path, ".webp"):
		return "GET", "image/webp"
	case strings.HasSuffix(path, ".ico"):
		return "GET", "image/x-icon"
	case strings.HasSuffix(path, ".woff2"):
		return "GET", "font/woff2"
	case strings.HasPrefix(path, "/sse"):
		return "GET", "text/event-stream"
	case strings.HasPrefix(path, "/api") || strings.HasPrefix(path, "/v1") || strings.HasPrefix(path, "/v2"):
		methods := []string{"GET", "GET", "GET", "POST", "PUT", "DELETE"}
		return methods[r.IntN(len(methods))], "application/json"
	case path == "/collect" || path == "/beacon":
		return "POST", "text/plain"
	default:
		return "GET", "text/html"
	}
}

func hostHeader(x Exchange) string {
	if (x.Scheme == "https" && x.Port == 443) || (x.Scheme == "http" && x.Port == 80) {
		return x.Host
	}
	return fmt.Sprintf("%s:%d", x.Host, x.Port)
}

func rawRequest(x Exchange) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", x.Method, x.Path)
	fmt.Fprintf(&b, "Host: %s\r\n", hostHeader(x))
	b.WriteString("User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15\r\n")
	b.WriteString("Accept: */*\r\n")
	if x.Method == "GET" || x.Method == "DELETE" {
		b.WriteString("\r\n")
		return b.String()
	}
	body := `{"name":"sluice","count":3}`
	if x.IsLLM {
		body = `{"model":"demo-model","stream":` + fmt.Sprint(x.MIME == "text/event-stream") +
			`,"messages":[{"role":"user","content":"Summarise this page in one line."}]}`
	}
	b.WriteString("Content-Type: application/json\r\n")
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n%s", len(body), body)
	return b.String()
}

func rawResponse(x Exchange) string {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", x.Status, reasons[x.Status])
	b.WriteString("Server: synth/0\r\n")
	if x.RespSize == 0 {
		b.WriteString("\r\n")
		return b.String()
	}
	fmt.Fprintf(&b, "Content-Type: %s\r\n", x.MIME)

	var body string
	switch x.MIME {
	case "text/event-stream":
		b.WriteString("Transfer-Encoding: chunked\r\n\r\n")
		b.WriteString("data: {\"delta\":\"Sluice is\"}\n\ndata: {\"delta\":\" a proxy.\"}\n\ndata: [DONE]\n\n")
		return b.String()
	case "application/json":
		body = `{"ok":true,"items":[{"id":1},{"id":2}]}`
		if x.IsLLM {
			body = `{"id":"chatcmpl-demo","choices":[{"message":{"role":"assistant","content":"Sluice is a proxy."}}]}`
		}
	case "text/html":
		body = "<!doctype html><html><head><title>Example</title></head><body>Hello</body></html>"
	default:
		body = fmt.Sprintf("[%d bytes of %s]", x.RespSize, x.MIME)
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n%s", x.RespSize, body)
	return b.String()
}

// Produce generates ratePerSec exchanges per second until ctx is done, handing
// each to publish. It paces against wall-clock time so the rate holds even when
// ticks are late, but never bursts more than one second of backlog (e.g. after sleep).
func (g Generator) Produce(ctx context.Context, ratePerSec int, nextID func() int64, publish func(Exchange) bool) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	start := time.Now()
	var sent int64
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			due := int64(now.Sub(start).Seconds() * float64(ratePerSec))
			if backlog := due - sent; backlog > int64(ratePerSec) {
				sent = due - int64(ratePerSec)
			}
			for ; sent < due; sent++ {
				// The backlog can be up to ratePerSec events; stop mid-burst on
				// cancel so nothing is published after the caller stops us.
				if ctx.Err() != nil {
					return
				}
				publish(g.Exchange(nextID(), now))
			}
		}
	}
}

// synthReason labels fake LLM rows as matched by the path rule, which is what
// the real detector would say for these endpoints (all but Gemini are known paths).
func synthReason(llm bool) string {
	if llm {
		return "path"
	}
	return ""
}
