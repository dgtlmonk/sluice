package testorigin

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func start(t *testing.T) string {
	t.Helper()
	addr, stop := Start()
	t.Cleanup(stop)
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("not loopback: %s", addr)
	}
	return addr
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func get(t *testing.T, c net.Conn, path string) {
	t.Helper()
	if _, err := io.WriteString(c, "GET "+path+" HTTP/1.1\r\nHost: origin\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
}

// readHead reads raw header lines up to the blank line.
func readHead(t *testing.T, br *bufio.Reader) string {
	t.Helper()
	var b strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("head: %v (so far %q)", err, b.String())
		}
		b.WriteString(line)
		if line == "\r\n" {
			return b.String()
		}
	}
}

func TestContentLength(t *testing.T) {
	c := dial(t, start(t))
	get(t, c, PathContentLength)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.ContentLength != int64(len(ContentLengthBody)) || len(resp.TransferEncoding) != 0 {
		t.Fatalf("CL=%d TE=%v", resp.ContentLength, resp.TransferEncoding)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != ContentLengthBody {
		t.Fatalf("body %q", body)
	}
}

func TestChunkedIsReallyChunkedOnWire(t *testing.T) {
	c := dial(t, start(t))
	get(t, c, PathChunked)
	br := bufio.NewReader(c)
	head := readHead(t, br)
	if !strings.Contains(head, "Transfer-Encoding: chunked\r\n") || strings.Contains(head, "Content-Length") {
		t.Fatalf("head %q", head)
	}
	// Each flushed part must be its own chunk: "<hex>\r\n<data>\r\n".
	var want strings.Builder
	for _, p := range ChunkParts {
		want.WriteString(strconv.FormatInt(int64(len(p)), 16) + "\r\n" + p + "\r\n")
	}
	want.WriteString("0\r\n\r\n")
	got := make([]byte, want.Len())
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != want.String() {
		t.Fatalf("wire\n got %q\nwant %q", got, want.String())
	}
}

func TestKeepAliveServesMultipleRequestsOnOneConn(t *testing.T) {
	c := dial(t, start(t))
	br := bufio.NewReader(c)
	for i := range 3 {
		get(t, c, PathKeepAlive)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("req %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(body) != KeepAliveBody || resp.Close {
			t.Fatalf("req %d: body %q close=%v", i, body, resp.Close)
		}
	}
}

func TestCloseIsCloseDelimited(t *testing.T) {
	c := dial(t, start(t))
	get(t, c, PathClose)
	raw, err := io.ReadAll(c) // returns only once the server closes.
	if err != nil {
		t.Fatal(err)
	}
	head, body, ok := strings.Cut(string(raw), "\r\n\r\n")
	if !ok {
		t.Fatalf("no head end: %q", raw)
	}
	if !strings.Contains(head, "Connection: close") ||
		strings.Contains(head, "Content-Length") || strings.Contains(head, "Transfer-Encoding") {
		t.Fatalf("head %q", head)
	}
	if body != CloseBody {
		t.Fatalf("body %q", body)
	}
}

func TestSSEArrivesIncrementally(t *testing.T) {
	c := dial(t, start(t))
	get(t, c, PathSSE)
	br := bufio.NewReader(c)
	head := readHead(t, br)
	if !strings.Contains(head, "Content-Type: text/event-stream") {
		t.Fatalf("head %q", head)
	}
	resp, err := http.ReadResponse(bufio.NewReader(io.MultiReader(strings.NewReader(head), br)), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	ev := bufio.NewReader(resp.Body)
	var arrivals []time.Time
	for _, want := range SSEEvents {
		line, err := ev.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		arrivals = append(arrivals, time.Now())
		if line != "data: "+want+"\n" {
			t.Fatalf("line %q", line)
		}
		if blank, _ := ev.ReadString('\n'); blank != "\n" {
			t.Fatalf("missing blank line, got %q", blank)
		}
	}
	// Total spread must reflect the server-side delays: events were not
	// buffered and delivered together.
	spread := arrivals[len(arrivals)-1].Sub(arrivals[0])
	if minSpread := SSEDelay * time.Duration(len(SSEEvents)-1) * 8 / 10; spread < minSpread {
		t.Fatalf("events bunched: spread %v < %v", spread, minSpread)
	}
}

func TestDeterministicBodies(t *testing.T) {
	addr := start(t)
	cases := map[string]string{
		PathContentLength: ContentLengthBody,
		PathChunked:       ChunkedBody(),
		PathKeepAlive:     KeepAliveBody,
		PathClose:         CloseBody,
		PathSSE:           SSEBody(),
	}
	client := &http.Client{Timeout: 5 * time.Second}
	for path, want := range cases {
		for range 2 {
			resp, err := client.Get("http://" + addr + path)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if string(body) != want {
				t.Fatalf("%s: %q", path, body)
			}
		}
	}
}

// RFC 9110 section 9.3.2: HEAD gets the GET head but no content, even on the
// hand-written close-delimited path.
func TestCloseHEADHasNoBody(t *testing.T) {
	c := dial(t, start(t))
	if _, err := io.WriteString(c, "HEAD "+PathClose+" HTTP/1.1\r\nHost: origin\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(c) // server closes after the head.
	if err != nil {
		t.Fatal(err)
	}
	head, body, ok := strings.Cut(string(raw), "\r\n\r\n")
	if !ok || !strings.HasPrefix(head, "HTTP/1.1 200 ") || !strings.Contains(head, "Connection: close") {
		t.Fatalf("head %q", raw)
	}
	if body != "" {
		t.Fatalf("HEAD got body %q", body)
	}
}

func TestChatAcceptsChunkedAndContentLengthBodies(t *testing.T) {
	addr := start(t)
	for _, te := range []bool{false, true} {
		c := dial(t, addr)
		req := "POST " + PathChat + " HTTP/1.1\r\nHost: origin\r\nContent-Type: application/json\r\n"
		body := `{"model":"m","messages":[]}`
		if te {
			req += "Transfer-Encoding: chunked\r\n\r\n" + strconv.FormatInt(int64(len(body)), 16) + "\r\n" + body + "\r\n0\r\n\r\n"
		} else {
			req += "Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
		}
		if _, err := io.WriteString(c, req); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || string(got) != ChatReply || resp.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("chunked=%v: status %d body %q", te, resp.StatusCode, got)
		}
	}
}

func TestStartTLSVerifiesWithOwnRoots(t *testing.T) {
	addr, roots, stop := StartTLS()
	t.Cleanup(stop)
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("not loopback: %s", addr)
	}
	c, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: roots, ServerName: TLSServerName, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if p := c.ConnectionState().NegotiatedProtocol; p != "http/1.1" {
		t.Fatalf("ALPN = %q", p)
	}
}
