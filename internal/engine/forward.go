package engine

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// clientConn is one accepted client connection. Exactly one goroutine
// (serve) reads and writes it; the server only Closes it on shutdown.
type clientConn struct {
	srv  *Server
	conn *timeoutConn
	br   *bufio.Reader
	bw   *bufio.Writer
	idle bool // guarded by srv.mu
	// tunnel is set once a CONNECT has been decrypted; from then on conn,
	// br and bw carry the plaintext inside TLS.
	tunnel *tunnel
}

// serve loops over requests on one client connection (client-side
// keep-alive) until either side wants to close, an error, or shutdown.
func (cc *clientConn) serve() {
	defer cc.srv.removeConn(cc)
	defer func() { _ = cc.conn.Close() }()
	for {
		if !cc.srv.setIdle(cc, true) {
			return
		}
		// Wait for the first byte of the next request before leaving the
		// idle state, so Shutdown can close a conn that is merely waiting.
		if _, err := cc.br.Peek(1); err != nil {
			return
		}
		if !cc.srv.setIdle(cc, false) {
			return
		}
		if !cc.handleOne() {
			return
		}
	}
}

// exchange carries the state of one request/response through the proxy.
type exchange struct {
	ex       Exchange
	req      *Request
	target   proxyTarget
	clientKA bool // the client asked to keep its connection open
	silent   bool // not published (a CONNECT that became a tunnel)
}

// handleOne proxies one request. It reports whether the client connection
// can carry another request.
func (cc *clientConn) handleOne() bool {
	s := cc.srv
	x := &exchange{ex: Exchange{ID: s.nextID.Add(1), Started: time.Now()}}
	defer func() {
		// A client that connected (or kept a conn alive) and then closed
		// without sending a request made no exchange; publishing one would
		// show an empty row. Parse errors set Err, so they are still shown.
		if x.silent || (x.ex.Method == "" && x.ex.Err == "") {
			return
		}
		x.ex.Duration = time.Since(x.ex.Started)
		s.publish(x.ex)
	}()

	// The first byte has arrived (serve peeked it); from here the whole head
	// must arrive within HeadReadTimeout, however slowly it trickles.
	cc.conn.beginHead(s.cfg.HeadReadTimeout)
	req, err := ReadRequest(cc.br, s.cfg.Limits)
	cc.conn.endHead()
	if err != nil {
		var pe *ParseError
		if errors.As(err, &pe) {
			x.ex.Err = pe.Reason
			cc.reject(x, pe.Status, pe.Reason)
		}
		// Anything else (EOF, reset, timeout) leaves nothing to answer.
		return false
	}
	x.req = req
	x.ex.Method = req.Method
	x.ex.Scheme = "http"
	if cc.tunnel != nil {
		x.ex.Scheme = "https"
	}
	s.tapHead(x.ex.ID, DirRequest, req.RawHead)

	if req.Method == "CONNECT" {
		return cc.handleConnect(x)
	}
	if status, reason := cc.checkRequest(x); status != 0 {
		x.ex.Err = reason
		cc.reject(x, status, reason)
		return false
	}
	x.ex.Host, x.ex.Path = x.target.authority, x.target.path
	x.clientKA = wantsKeepAlive(req.Minor, req.Headers)
	return cc.roundTrip(x)
}

// checkRequest applies the proxy's own rules on top of the parser's. It
// returns a non-zero status when the request must be refused.
func (cc *clientConn) checkRequest(x *exchange) (int, string) {
	req := x.req
	var t proxyTarget
	var err error
	if cc.tunnel != nil {
		t, err = cc.tunnel.target(req.Target)
	} else {
		t, err = parseAbsoluteTarget(req.Target)
	}
	if err != nil {
		return 400, err.Error()
	}
	if err := checkConnectionTokens(req.Headers); err != nil {
		return 400, err.Error()
	}
	x.target = t
	return 0, ""
}

// upstreamRequestHead builds the head sent to the origin: origin-form target,
// Host set to the target authority, hop-by-hop fields removed.
//
// RFC 9112 §3.2.2: when a proxy receives absolute-form it MUST ignore the
// received Host and replace it with the URI's authority. Otherwise a request
// for http://a/ with "Host: b" could be routed to a but read as b (a cache-
// poisoning and routing-confusion trick).
//
// The proxy always speaks HTTP/1.1 upstream; the version is per hop.
func upstreamRequestHead(req *Request, t proxyTarget) (string, Headers) {
	h := stripHopByHop(req.Headers)
	h = withoutField(h, "Host")
	if expects100Continue(req) {
		// The proxy answers the client's Expect itself (see roundTrip), so
		// the origin must not be asked to send a second 100 Continue.
		h = withoutField(h, "Expect")
	}
	h = append(Headers{{Name: "Host", Value: t.authority}}, h...)
	return req.Method + " " + t.path + " HTTP/1.1", h
}

// roundTrip forwards the request, streams the response back, and reports
// whether the client connection stays usable.
func (cc *clientConn) roundTrip(x *exchange) bool {
	s := cc.srv
	req := x.req
	key := poolKey(x.target)
	start, headers := upstreamRequestHead(req, x.target)
	body := tapBody(req.Body, s.tapFor(x.ex.ID, DirRequest))

	if expects100Continue(req) {
		// RFC 9110 §10.1.1: a client sending "Expect: 100-continue" may hold
		// its body until it sees 100 Continue. The proxy reads the body before
		// it reads anything from the origin, so if it waited for the origin's
		// 100 both sides would wait forever (the origin for the body, the
		// client for the 100). A proxy is allowed to answer the expectation
		// itself, so it sends 100 now and strips Expect upstream. The cost:
		// the origin can no longer refuse the upload before it is sent.
		_, _ = cc.bw.WriteString("HTTP/1.1 100 Continue\r\n\r\n")
		if err := cc.bw.Flush(); err != nil {
			return false
		}
	}

	up := s.pool.get(key)
	reused := up != nil
	for attempt := 0; ; attempt++ {
		if up == nil {
			var err error
			if up, err = s.dial(key, x.target); err != nil {
				return cc.upstreamFailed(x, err)
			}
		}
		resp, n, err := cc.sendRequest(up, start, headers, body, req.Framing.Kind == FramingChunked)
		x.ex.ReqBytes = n
		if err == nil {
			return cc.relayResponse(x, up, resp)
		}
		up.close()
		var rerr *requestBodyError
		if errors.As(err, &rerr) {
			// The client's own body was malformed or truncated mid-stream.
			var pe *ParseError
			if errors.As(rerr.err, &pe) {
				x.ex.Err = pe.Reason
				cc.reject(x, pe.Status, pe.Reason)
			}
			return false
		}
		// A pooled connection may have been closed by the origin while it sat
		// idle; that race shows up as EOF/reset before any response byte.
		// But the origin may also have received and acted on the request
		// before the conn died, so a retry is only safe for idempotent
		// methods (RFC 9110 §9.2.2: repeating them has the same effect as
		// sending once) and only when no body was consumed from the client
		// (nothing would be lost). POST, PATCH and CONNECT are never retried.
		if attempt == 0 && reused && req.Framing.Kind == FramingNone && isIdempotent(req.Method) && isStaleConnErr(err) {
			up = nil
			continue
		}
		return cc.upstreamFailed(x, err)
	}
}

// isIdempotent lists the RFC 9110 §9.2.2 idempotent methods.
func isIdempotent(method string) bool {
	switch method {
	case "GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE":
		return true
	}
	return false
}

// expects100Continue reports whether the client will wait for a 100
// Continue before sending its body. Only HTTP/1.1 clients do this (1xx does
// not exist in 1.0), and only a request that has a body has anything to hold.
func expects100Continue(req *Request) bool {
	if req.Minor != 1 || req.Framing.Kind == FramingNone {
		return false
	}
	for _, v := range req.Headers.Values("Expect") {
		if strings.EqualFold(strings.TrimSpace(v), "100-continue") {
			return true
		}
	}
	return false
}

// requestBodyError marks a failure reading the client's request body.
type requestBodyError struct{ err error }

func (e *requestBodyError) Error() string { return "request body: " + e.err.Error() }
func (e *requestBodyError) Unwrap() error { return e.err }

func (s *Server) dial(key string, t proxyTarget) (*upstreamConn, error) {
	d := net.Dialer{Timeout: s.cfg.DialTimeout}
	c, err := d.Dial("tcp", t.addr)
	if err != nil {
		return nil, err
	}
	if t.tls {
		if c, err = s.dialTLS(c, t.serverName); err != nil {
			return nil, err
		}
	}
	tc := &timeoutConn{Conn: c, readTimeout: s.cfg.UpstreamIdleTimeout, writeTimeout: s.cfg.UpstreamIdleTimeout}
	return &upstreamConn{key: key, conn: tc, br: bufio.NewReader(tc), bw: bufio.NewWriter(tc)}, nil
}

// sendRequest writes head and body upstream, then reads the response head.
// Request body bytes are streamed as they arrive from the client. It also
// returns how many decoded body bytes were forwarded.
func (cc *clientConn) sendRequest(up *upstreamConn, start string, h Headers, body io.Reader, chunked bool) (*Response, int64, error) {
	if err := writeHead(up.bw, start, h); err != nil {
		return nil, 0, err
	}
	res := copyBody(up.bw, body, chunked, false)
	if res.readErr != nil {
		return nil, res.n, &requestBodyError{err: res.readErr}
	}
	if res.writeErr != nil {
		return nil, res.n, res.writeErr
	}
	if chunked {
		var trailers Headers
		if cr, ok := body.(*ChunkedReader); ok {
			trailers = cr.Trailers()
		}
		if err := writeLastChunk(up.bw, trailers); err != nil {
			return nil, res.n, err
		}
	}
	if err := up.bw.Flush(); err != nil {
		return nil, res.n, err
	}
	resp, err := cc.readResponseHead(up, reqMethodOf(start))
	return resp, res.n, err
}

// readResponseHead reads one response head from the origin. The origin gets
// ResponseHeaderTimeout to deliver the whole head (an absolute cap, so a
// byte-trickling origin cannot stretch it); after the head, the body is
// governed by the (longer) idle timeout.
func (cc *clientConn) readResponseHead(up *upstreamConn, method string) (*Response, error) {
	cfg := cc.srv.cfg
	up.conn.readTimeout = cfg.ResponseHeaderTimeout
	up.conn.beginHead(cfg.ResponseHeaderTimeout)
	defer func() {
		up.conn.endHead()
		up.conn.readTimeout = cfg.UpstreamIdleTimeout
	}()
	return ReadResponse(up.br, cfg.Limits, method)
}

func reqMethodOf(startLine string) string {
	for i := 0; i < len(startLine); i++ {
		if startLine[i] == ' ' {
			return startLine[:i]
		}
	}
	return startLine
}

func isStaleConnErr(err error) bool {
	// io.ErrUnexpectedEOF is deliberately absent: it means part of a
	// response arrived, so the origin did see the request.
	return errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}

// relayResponse forwards 1xx interim responses, then the final response,
// re-encoding the body framing for the client where needed.
func (cc *clientConn) relayResponse(x *exchange, up *upstreamConn, resp *Response) bool {
	s := cc.srv
	var err error
	// 1xx responses (e.g. 100 Continue, 103 Early Hints) precede the final
	// one. 101 Switching Protocols cannot happen legitimately because the
	// proxy strips Upgrade, so it is treated as a broken origin.
	for resp.StatusCode < 200 {
		if resp.StatusCode == 101 {
			up.close()
			return cc.upstreamFailed(x, errors.New("unexpected 101 Switching Protocols"))
		}
		if x.req.Minor == 1 { // HTTP/1.0 clients do not understand 1xx
			_ = writeHead(cc.bw, statusLine(resp), stripHopByHop(resp.Headers))
			if err := cc.bw.Flush(); err != nil {
				up.close()
				return false
			}
		}
		resp, err = cc.readResponseHead(up, x.req.Method)
		if err != nil {
			up.close()
			return cc.upstreamFailed(x, err)
		}
	}
	if err := checkConnectionTokens(resp.Headers); err != nil {
		up.close()
		return cc.upstreamFailed(x, err)
	}

	plan := planResponse(x.req.Minor, x.clientKA, resp)
	x.ex.Status = resp.StatusCode
	s.tapHead(x.ex.ID, DirResponse, resp.RawHead)
	_ = writeHead(cc.bw, statusLine(resp), plan.headers)
	if err := cc.bw.Flush(); err != nil {
		up.close()
		return false
	}

	body := tapBody(resp.Body, s.tapFor(x.ex.ID, DirResponse))
	res := copyBody(cc.bw, body, plan.chunkOut, true)
	x.ex.RespBytes = res.n
	if res.readErr != nil || res.writeErr != nil {
		// Headers are already out, so no error status can be sent. Closing
		// the client conn without the terminating chunk (or short of
		// Content-Length) is how the client learns the body is incomplete.
		up.close()
		if res.readErr != nil {
			x.ex.Err = "upstream body: " + res.readErr.Error()
		} else {
			x.ex.Err = "client write: " + res.writeErr.Error()
		}
		return false
	}
	if plan.chunkOut {
		var trailers Headers
		if cr, ok := resp.Body.(*ChunkedReader); ok {
			trailers = cr.Trailers()
		}
		_ = writeLastChunk(cc.bw, trailers)
	}
	if err := cc.bw.Flush(); err != nil {
		up.close()
		return false
	}
	if plan.upstreamReusable {
		s.pool.put(up)
	} else {
		up.close()
	}
	return plan.clientKeepAlive
}

func statusLine(resp *Response) string {
	line := "HTTP/1.1 " + strconv.Itoa(resp.StatusCode)
	if resp.Reason != "" {
		line += " " + resp.Reason
	}
	return line
}

// responsePlan is how the response is framed toward the client.
type responsePlan struct {
	headers          Headers
	chunkOut         bool
	clientKeepAlive  bool
	upstreamReusable bool
}

// planResponse decides the client-side framing. The proxy decodes the
// origin's framing and re-encodes it, so the two legs can differ:
//
//	origin framing    client 1.1                 client 1.0
//	none / CL         as-is                      as-is
//	chunked           re-chunked                 close-delimited, then close
//	close-delimited   chunked (conn kept alive)  close-delimited, then close
//
// HTTP/1.0 has no chunked coding, so for a 1.0 client the only way to send
// a body of unknown length is to close the connection after it.
func planResponse(clientMinor int, clientKA bool, resp *Response) responsePlan {
	h := stripHopByHop(resp.Headers)
	p := responsePlan{clientKeepAlive: clientKA}
	switch resp.Framing.Kind {
	case FramingChunked:
		if clientMinor == 1 {
			p.chunkOut = true
		} else {
			h = withoutField(h, "Transfer-Encoding")
			p.clientKeepAlive = false
		}
	case FramingCloseDelimited:
		if clientMinor == 1 {
			p.chunkOut = true
			h = append(h, Header{Name: "Transfer-Encoding", Value: "chunked"})
		} else {
			p.clientKeepAlive = false
		}
	}
	// A close-delimited body consumes the upstream connection by definition.
	p.upstreamReusable = resp.Framing.Kind != FramingCloseDelimited && wantsKeepAlive(resp.Minor, resp.Headers)
	switch {
	case !p.clientKeepAlive:
		h = append(h, Header{Name: "Connection", Value: "close"})
	case clientMinor == 0:
		h = append(h, Header{Name: "Connection", Value: "keep-alive"})
	}
	p.headers = h
	return p
}

// upstreamFailed answers the client when the origin could not be reached or
// misbehaved before any response byte was relayed: 504 for a timeout, 502
// for everything else (refused, reset, unparsable response).
func (cc *clientConn) upstreamFailed(x *exchange, err error) bool {
	status, msg := 502, "bad gateway: "+err.Error()
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		status, msg = 504, "gateway timeout: "+err.Error()
	}
	x.ex.Err = msg
	cc.reject(x, status, msg)
	return false
}

// reject writes a small proxy-generated error response and marks the
// connection for closing (the caller returns false).
func (cc *clientConn) reject(x *exchange, status int, msg string) {
	x.ex.Status = status
	body := msg + "\n"
	h := Headers{
		{Name: "Content-Type", Value: "text/plain; charset=utf-8"},
		{Name: "Content-Length", Value: strconv.Itoa(len(body))},
		{Name: "Connection", Value: "close"},
	}
	if status == 405 { // RFC 9110 §15.5.6: a 405 MUST list what is allowed
		h = append(h, Header{Name: "Allow", Value: "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, CONNECT"})
	}
	// Build the head in memory first so the history records exactly the
	// bytes the client got, then send them.
	var head bytes.Buffer
	hw := bufio.NewWriter(&head)
	_ = writeHead(hw, "HTTP/1.1 "+strconv.Itoa(status)+" "+reasonPhrase(status), h)
	_ = hw.Flush()
	s := cc.srv
	s.tapHead(x.ex.ID, DirResponse, head.Bytes())
	if tap := s.tapFor(x.ex.ID, DirResponse); tap != nil {
		tap([]byte(body))
	}
	_, _ = cc.bw.Write(head.Bytes())
	_, _ = cc.bw.WriteString(body)
	_ = cc.bw.Flush()
}

func reasonPhrase(status int) string {
	switch status {
	case 400:
		return "Bad Request"
	case 405:
		return "Method Not Allowed"
	case 501:
		return "Not Implemented"
	case 431:
		return "Request Header Fields Too Large"
	case 502:
		return "Bad Gateway"
	case 504:
		return "Gateway Timeout"
	case 505:
		return "HTTP Version Not Supported"
	}
	return "Error"
}
