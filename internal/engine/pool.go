package engine

import (
	"bufio"
	"errors"
	"net"
	"sync"
	"time"
)

// upstreamConn is one connection to an origin plus its buffers. The reader
// must survive between exchanges: bytes the origin sent early would be lost
// if a fresh bufio.Reader were made per request.
type upstreamConn struct {
	key       string
	conn      *timeoutConn
	br        *bufio.Reader
	bw        *bufio.Writer
	idleSince time.Time
}

func (u *upstreamConn) close() { _ = u.conn.Close() }

// quiet reports whether an idle conn is still clean: nothing buffered and
// nothing readable on the socket. On an idle keep-alive connection the
// origin has no right to send anything, so any readable state means
// trouble: EOF/RST (the origin closed it while it sat in the pool), or
// unsolicited bytes (a buggy or hostile origin; reusing the conn would make
// those bytes the start of the next response, a response-splitting desync).
//
// The check is a 1-byte read with a 1ms deadline, which makes it almost
// non-blocking: a timeout error means "nothing to read", i.e. the conn is
// healthy. (A deadline already in the past would not work: Go's poller
// reports the timeout without even trying the read syscall, so pending
// bytes or a FIN would go unseen.) It cannot catch a close that is still in flight;
// the stale-conn retry in roundTrip covers that race.
func (u *upstreamConn) quiet() bool {
	if u.br.Buffered() > 0 {
		return false
	}
	_ = u.conn.SetReadDeadline(time.Now().Add(time.Millisecond))
	// Bypass timeoutConn.Read, which would replace the deadline.
	_, err := u.conn.Conn.Read(make([]byte, 1))
	_ = u.conn.SetReadDeadline(time.Time{})
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// poolKey identifies interchangeable connections. TLS is in the key so an
// http and an https connection to the same host:port are never handed out
// for each other, and so is the server name: a TLS conn was verified for
// one name (SNI), and reusing it for another would skip that check.
func poolKey(t proxyTarget) string {
	if t.tls {
		return t.addr + "|tls|" + t.serverName
	}
	return t.addr + "|plain"
}

// connPool keeps idle upstream connections for reuse (keep-alive on the
// upstream leg). Bounds: maxIdlePerKey per key and idleTimeout age; see the
// SPEC.md optimization backlog for a global cap and background reaping.
type connPool struct {
	mu            sync.Mutex
	idle          map[string][]*upstreamConn
	maxIdlePerKey int
	idleTimeout   time.Duration
	closed        bool
}

func newConnPool(maxIdlePerKey int, idleTimeout time.Duration) *connPool {
	return &connPool{idle: map[string][]*upstreamConn{}, maxIdlePerKey: maxIdlePerKey, idleTimeout: idleTimeout}
}

// get returns the most recently used live idle connection for key, or nil.
// Connections idle past idleTimeout are closed on the way: the origin has
// probably dropped them already, and reusing one would just fail.
func (p *connPool) get(key string) *upstreamConn {
	p.mu.Lock()
	defer p.mu.Unlock()
	list := p.idle[key]
	for len(list) > 0 {
		u := list[len(list)-1]
		list = list[:len(list)-1]
		if time.Since(u.idleSince) <= p.idleTimeout && u.quiet() {
			p.idle[key] = list
			return u
		}
		u.close()
	}
	delete(p.idle, key)
	return nil
}

// put returns a clean connection (both messages fully transferred) to the pool.
func (p *connPool) put(u *upstreamConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || len(p.idle[u.key]) >= p.maxIdlePerKey {
		u.close()
		return
	}
	u.idleSince = time.Now()
	p.idle[u.key] = append(p.idle[u.key], u)
}

// closeAll closes every idle connection and refuses new ones.
func (p *connPool) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for k, list := range p.idle {
		for _, u := range list {
			u.close()
		}
		delete(p.idle, k)
	}
}
