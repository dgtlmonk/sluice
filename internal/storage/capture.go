package storage

import "sync"

// MaxStoredBody caps the stored copy of each body (SPEC.md, Storage: 32 MB).
// Forwarding is never truncated; only what reaches the database is, and the
// message is flagged so the UI can say so.
const MaxStoredBody = 32 << 20

// Capture assembles the raw bytes of in-flight exchanges from the engine's
// taps (heads arrive whole, bodies in pieces as they stream) until the
// exchange is finished. It is keyed by the engine's exchange id and knows
// nothing about the engine itself, so storage does not import it.
//
// The taps run inline on forwarding goroutines, so every method only copies
// bytes under a short lock.
type Capture struct {
	maxBody int

	mu     sync.Mutex
	drafts map[uint64]*draft
}

type draft struct{ req, resp Message }

// NewCapture returns a Capture storing at most maxBody bytes per body
// (MaxStoredBody when maxBody <= 0).
func NewCapture(maxBody int) *Capture {
	if maxBody <= 0 {
		maxBody = MaxStoredBody
	}
	return &Capture{maxBody: maxBody, drafts: map[uint64]*draft{}}
}

func (c *Capture) msg(id uint64, response bool) *Message {
	d := c.drafts[id]
	if d == nil {
		d = &draft{}
		c.drafts[id] = d
	}
	if response {
		return &d.resp
	}
	return &d.req
}

// Head records a message head. raw is copied; the caller may reuse it.
func (c *Capture) Head(id uint64, response bool, raw []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := c.msg(id, response)
	m.RawHeaders = append([]byte(nil), raw...)
}

// Body appends a piece of a body, up to the cap. raw is copied.
func (c *Capture) Body(id uint64, response bool, raw []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := c.msg(id, response)
	room := c.maxBody - len(m.RawBody)
	if room <= 0 {
		m.BodyTruncated = m.BodyTruncated || len(raw) > 0
		return
	}
	if len(raw) > room {
		raw = raw[:room]
		m.BodyTruncated = true
	}
	m.RawBody = append(m.RawBody, raw...)
}

// Finish removes and returns what was captured for id. A side with no head
// and no body comes back nil (for example, no response was ever received).
func (c *Capture) Finish(id uint64) (req, resp *Message) {
	c.mu.Lock()
	d := c.drafts[id]
	delete(c.drafts, id)
	c.mu.Unlock()
	if d == nil {
		return nil, nil
	}
	return nilIfEmpty(d.req), nilIfEmpty(d.resp)
}

// Pending reports how many exchanges are mid-capture.
func (c *Capture) Pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.drafts)
}

func nilIfEmpty(m Message) *Message {
	if m.RawHeaders == nil && m.RawBody == nil {
		return nil
	}
	return &m
}
