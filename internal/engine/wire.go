package engine

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"time"
)

// writeHead serializes a start line and fields. The head is rebuilt rather
// than copied from RawHead because the proxy must change it (origin-form
// target, Host, hop-by-hop removal); every field it keeps goes out with its
// original name case and order.
func writeHead(w *bufio.Writer, startLine string, h Headers) error {
	_, _ = w.WriteString(startLine)
	_, _ = w.WriteString("\r\n")
	for _, f := range h {
		_, _ = w.WriteString(f.Name)
		_, _ = w.WriteString(": ")
		_, _ = w.WriteString(f.Value)
		_, _ = w.WriteString("\r\n")
	}
	_, err := w.WriteString("\r\n")
	return err // bufio.Writer errors are sticky, so the last one covers all
}

// writeChunk writes one chunk: hex size, CRLF, data, CRLF (RFC 9112 §7.1).
// An empty p would be the last-chunk marker, so it is skipped here.
func writeChunk(w *bufio.Writer, p []byte) error {
	if len(p) == 0 {
		return nil
	}
	_, _ = w.WriteString(strconv.FormatInt(int64(len(p)), 16))
	_, _ = w.WriteString("\r\n")
	_, _ = w.Write(p)
	_, err := w.WriteString("\r\n")
	return err
}

// writeLastChunk ends a chunked body: "0" CRLF, any trailer fields, CRLF.
func writeLastChunk(w *bufio.Writer, trailers Headers) error {
	_, _ = w.WriteString("0\r\n")
	for _, f := range trailers {
		_, _ = w.WriteString(f.Name + ": " + f.Value + "\r\n")
	}
	_, err := w.WriteString("\r\n")
	return err
}

// copyResult separates which side failed, because the proxy reacts
// differently: a read error is the sender's fault, a write error the receiver's.
type copyResult struct {
	n        int64
	readErr  error
	writeErr error
}

// copyBody streams src to w. With chunked it re-applies chunk framing to
// each piece read; with flush it pushes every piece to the socket at once,
// which is what lets chunked and SSE responses reach the client as they are
// produced instead of when a buffer happens to fill.
func copyBody(w *bufio.Writer, src io.Reader, chunked, flush bool) copyResult {
	var res copyResult
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			res.n += int64(n)
			var werr error
			if chunked {
				werr = writeChunk(w, buf[:n])
			} else {
				_, werr = w.Write(buf[:n])
			}
			if werr == nil && flush {
				werr = w.Flush()
			}
			if werr != nil {
				res.writeErr = werr
				return res
			}
		}
		if err == io.EOF { //nolint:errorlint // io.Reader contract: EOF is returned unwrapped
			return res
		}
		if err != nil {
			res.readErr = err
			return res
		}
	}
}

// tapBody makes the raw wire bytes of a body visible to tap (for later
// storage). For chunked bodies the decoder itself reports the framing it
// consumes; for the other framings decoded bytes are the raw bytes.
func tapBody(body io.Reader, tap func([]byte)) io.Reader {
	if tap == nil {
		return body
	}
	if cr, ok := body.(*ChunkedReader); ok {
		cr.SetRawTap(tap)
		return body
	}
	return &tapReader{r: body, tap: tap}
}

type tapReader struct {
	r   io.Reader
	tap func([]byte)
}

func (t *tapReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if n > 0 {
		t.tap(p[:n])
	}
	return n, err
}

// timeoutConn renews a deadline before every Read and Write, which turns a
// fixed timeout into an idle timeout: a stream that keeps moving (an SSE
// feed, a large download) lives as long as it needs, a stalled one dies.
// readTimeout may be changed between phases by the goroutine that owns the
// conn (for example a shorter wait for a response head).
//
// An idle timeout alone cannot stop a slowloris peer: one byte every few
// seconds renews it forever. While a message head is being read, headDeadline
// adds an absolute cap; each Read uses whichever deadline comes first.
type timeoutConn struct {
	net.Conn
	readTimeout  time.Duration
	writeTimeout time.Duration
	headDeadline time.Time // zero when not reading a head
}

// beginHead caps the time left to finish reading the current message head.
func (c *timeoutConn) beginHead(d time.Duration) { c.headDeadline = time.Now().Add(d) }

// endHead lifts the cap once the head is parsed; the body is governed by
// the idle timeout only (a long download must not be cut off).
func (c *timeoutConn) endHead() { c.headDeadline = time.Time{} }

func (c *timeoutConn) Read(p []byte) (int, error) {
	var dl time.Time
	if c.readTimeout > 0 {
		dl = time.Now().Add(c.readTimeout)
	}
	if !c.headDeadline.IsZero() && (dl.IsZero() || c.headDeadline.Before(dl)) {
		dl = c.headDeadline
	}
	if !dl.IsZero() {
		_ = c.SetReadDeadline(dl)
	}
	return c.Conn.Read(p)
}

func (c *timeoutConn) Write(p []byte) (int, error) {
	if c.writeTimeout > 0 {
		_ = c.SetWriteDeadline(time.Now().Add(c.writeTimeout))
	}
	return c.Conn.Write(p)
}
