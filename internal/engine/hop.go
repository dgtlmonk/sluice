package engine

import (
	"errors"
	"strings"
)

// hopByHop are the fields that describe one connection, not the message
// (RFC 9110 §7.6.1). A proxy consumes them and must not forward them.
// Proxy-Connection is non-standard but old clients still send it.
// Proxy-Authorization carries credentials meant for this proxy only.
var hopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "TE", "Trailer",
	"Upgrade", "Proxy-Authorization", "Proxy-Authenticate",
}

// protectedFromConnection are fields a Connection header may not nominate.
//
// "Connection: Content-Length" asks every hop to strip Content-Length. A
// proxy that frames the body by Content-Length and then obeys the strip
// forwards a body with no length signal, so the origin reads the body bytes
// as the next request: a hop-by-hop smuggling/desync trick. Host is here for
// the same reason on the routing side.
var protectedFromConnection = []string{"content-length", "transfer-encoding", "host"}

var errConnectionNamesFraming = errors.New("connection header nominates a framing or routing field")

// connectionTokens returns the lowercased option names listed in Connection
// (and the legacy Proxy-Connection) fields.
func connectionTokens(h Headers) []string {
	var out []string
	for _, f := range h {
		if !strings.EqualFold(f.Name, "Connection") && !strings.EqualFold(f.Name, "Proxy-Connection") {
			continue
		}
		for _, e := range strings.Split(f.Value, ",") {
			if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
				out = append(out, e)
			}
		}
	}
	return out
}

func hasToken(tokens []string, want string) bool {
	for _, t := range tokens {
		if t == want {
			return true
		}
	}
	return false
}

// checkConnectionTokens rejects a Connection header naming a protected field.
func checkConnectionTokens(h Headers) error {
	for _, t := range connectionTokens(h) {
		if hasToken(protectedFromConnection, t) {
			return errConnectionNamesFraming
		}
	}
	return nil
}

// stripHopByHop returns a copy of h without hop-by-hop fields and without
// any field named in Connection. Order and original case are kept.
func stripHopByHop(h Headers) Headers {
	drop := connectionTokens(h)
	out := make(Headers, 0, len(h))
	for _, f := range h {
		name := strings.ToLower(f.Name)
		if hasToken(drop, name) || isHopByHop(name) {
			continue
		}
		out = append(out, f)
	}
	return out
}

func isHopByHop(lowerName string) bool {
	for _, n := range hopByHop {
		if strings.EqualFold(n, lowerName) {
			return true
		}
	}
	return false
}

// wantsKeepAlive applies RFC 9112 §9.3: HTTP/1.1 is persistent unless
// "close" is listed; HTTP/1.0 is persistent only if "keep-alive" is listed.
func wantsKeepAlive(minor int, h Headers) bool {
	tokens := connectionTokens(h)
	if hasToken(tokens, "close") {
		return false
	}
	if minor == 0 {
		return hasToken(tokens, "keep-alive")
	}
	return true
}

// withoutField returns h minus every field named name.
func withoutField(h Headers, name string) Headers {
	out := make(Headers, 0, len(h))
	for _, f := range h {
		if !strings.EqualFold(f.Name, name) {
			out = append(out, f)
		}
	}
	return out
}
