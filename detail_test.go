package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dgtlmonk/sluice/internal/storage"
)

// detailApp builds an App whose bridge reads from a fresh test store.
func detailApp(t *testing.T, exs ...storage.Exchange) *App {
	t.Helper()
	st := openTestStore(t)
	for _, ex := range exs {
		if _, err := st.InsertExchange(context.Background(), ex); err != nil {
			t.Fatal(err)
		}
	}
	a := NewApp()
	a.devSynth = false
	a.proxy.useStore(st, "")
	return a
}

func storedExchange(id int64, req, resp *storage.Message) storage.Exchange {
	return storage.Exchange{ID: id, StartedAt: time.UnixMilli(1), Scheme: "http", Host: "h", Port: 80,
		Method: "GET", Path: "/", Status: 200, Tool: "proxy", Request: req, Response: resp}
}

func TestExchangeDetailHeadersWireOrderAndDuplicates(t *testing.T) {
	req := &storage.Message{RawHeaders: []byte("GET / HTTP/1.1\r\nHost: h\r\nX-A: 1\r\nCookie: a=1\r\nx-a:  2 \r\nCookie: b=2\r\n\r\n")}
	resp := &storage.Message{
		RawHeaders: []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nSet-Cookie: s=1\r\nSet-Cookie: t=2\r\n\r\n"),
		RawBody:    []byte("5\r\nhello\r\n0\r\n\r\n"),
	}
	d, err := detailApp(t, storedExchange(7, req, resp)).ExchangeDetail(7)
	if err != nil {
		t.Fatal(err)
	}
	if d.ID != 7 || d.Request.StartLine != "GET / HTTP/1.1" || d.Response.StartLine != "HTTP/1.1 200 OK" {
		t.Fatalf("view = %+v", d)
	}
	want := []HeaderField{{Name: "Host", Value: "h"}, {Name: "X-A", Value: "1"}, {Name: "Cookie", Value: "a=1"},
		{Name: "x-a", Value: "2"}, {Name: "Cookie", Value: "b=2"}}
	if len(d.Request.Headers) != len(want) {
		t.Fatalf("headers = %+v", d.Request.Headers)
	}
	for i := range want {
		if d.Request.Headers[i] != want[i] {
			t.Fatalf("header %d = %+v, want %+v", i, d.Request.Headers[i], want[i])
		}
	}
	if n := len(d.Response.Headers); n != 3 || d.Response.Headers[2].Value != "t=2" {
		t.Fatalf("response headers = %+v", d.Response.Headers)
	}
	// Chunk framing is shown as stored, not decoded.
	if d.Response.Body != "5\nhello\n0\n\n" || d.Response.BodyEncoding != encodingText {
		t.Fatalf("body = %q (%s)", d.Response.Body, d.Response.BodyEncoding)
	}
}

func TestExchangeDetailBinaryBodyIsHexDumped(t *testing.T) {
	bin := []byte{0x89, 'P', 'N', 'G', 0x00, 0xff, 0xfe, '<', 's', '>'}
	resp := &storage.Message{RawHeaders: []byte("HTTP/1.1 200 OK\r\n\r\n"), RawBody: bin}
	d, err := detailApp(t, storedExchange(1, nil, resp)).ExchangeDetail(1)
	if err != nil {
		t.Fatal(err)
	}
	if d.Response.BodyEncoding != encodingHex || !strings.HasPrefix(d.Response.Body, "00000000  89 50 4e 47 00 ff fe 3c") ||
		!strings.Contains(d.Response.Body, "|.PNG...<s>|") {
		t.Fatalf("body = %q", d.Response.Body)
	}
	if d.Request.Captured || d.Request.Headers == nil {
		t.Fatalf("missing request should be uncaptured with empty headers: %+v", d.Request)
	}
	// The binding result must survive JSON (the Wails bridge) as valid text.
	if _, err := json.Marshal(d); err != nil {
		t.Fatal(err)
	}
}

func TestExchangeDetailControlCharsVisible(t *testing.T) {
	req := &storage.Message{RawHeaders: []byte("GET / HTTP/1.1\r\nX-Evil: a\rb\x00c\u202ed\xff\r\nNoColon\r\n folded\r\n\r\n")}
	d, err := detailApp(t, storedExchange(2, req, nil)).ExchangeDetail(2)
	if err != nil {
		t.Fatal(err)
	}
	h := d.Request.Headers
	if len(h) != 3 || h[0].Value != `a\x0db\x00c\u{202e}d\xff` || !h[1].Malformed || !h[2].Malformed {
		t.Fatalf("headers = %+v", h)
	}
}

func TestExchangeDetailTruncation(t *testing.T) {
	// "é" is two bytes; place one across the view cut so the view must back up.
	body := []byte(strings.Repeat("a", maxDetailBody-1) + "é" + strings.Repeat("b", 100))
	resp := &storage.Message{RawHeaders: []byte("HTTP/1.1 200 OK\r\n\r\n"), RawBody: body, BodyTruncated: true}
	d, err := detailApp(t, storedExchange(3, nil, resp)).ExchangeDetail(3)
	if err != nil {
		t.Fatal(err)
	}
	r := d.Response
	if !r.BodyTruncated || !r.BodyViewTruncated || r.BodyBytes != len(body) || r.BodyShown != maxDetailBody-1 ||
		r.BodyEncoding != encodingText {
		t.Fatalf("view flags = %+v", MessageView{BodyTruncated: r.BodyTruncated, BodyViewTruncated: r.BodyViewTruncated,
			BodyBytes: r.BodyBytes, BodyShown: r.BodyShown, BodyEncoding: r.BodyEncoding})
	}

	small := &storage.Message{RawHeaders: []byte("HTTP/1.1 200 OK\r\n\r\n"), RawBody: []byte("x")}
	d, err = detailApp(t, storedExchange(4, nil, small)).ExchangeDetail(4)
	if err != nil {
		t.Fatal(err)
	}
	if d.Response.BodyTruncated || d.Response.BodyViewTruncated || d.Response.BodyShown != 1 {
		t.Fatalf("small = %+v", d.Response)
	}
}

func TestExchangeDetailUnknownID(t *testing.T) {
	if _, err := detailApp(t).ExchangeDetail(999); err == nil || !strings.Contains(err.Error(), "not in the store") {
		t.Fatalf("err = %v", err)
	}
	a := NewApp()
	a.devSynth = false
	if _, err := a.ExchangeDetail(1); err == nil {
		t.Fatal("no store: want error")
	}
}

func TestExchangeDetailSynthetic(t *testing.T) {
	a := NewApp()
	a.devSynth = true
	d, err := a.ExchangeDetail(5)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Synthetic || d.Request.StartLine == "" || len(d.Request.Headers) == 0 {
		t.Fatalf("synthetic = %+v", d)
	}
}
