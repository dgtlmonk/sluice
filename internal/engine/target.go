package engine

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

// proxyTarget is where an absolute-form request goes.
type proxyTarget struct {
	authority string // as written in the URI ("example.com:8080"); becomes Host
	addr      string // host:port to dial (port defaulted to 80)
	path      string // origin-form: "/path?query"
}

var (
	errNotAbsolute  = errors.New("proxy requests must use absolute-form (http://host/path)")
	errHTTPSTarget  = errors.New("https:// targets need CONNECT (not supported yet)")
	errBadScheme    = errors.New("only http:// targets are supported")
	errBadAuthority = errors.New("invalid authority in request target")
)

// parseAbsoluteTarget splits an absolute-form request target (RFC 9112
// §3.2.2), the form a client uses when it knows it is talking to a proxy:
//
//	GET http://example.com:8080/a?b HTTP/1.1
//
// The upstream origin expects origin-form ("/a?b"), so the proxy splits the
// URI into the authority (dial address + Host) and the path.
func parseAbsoluteTarget(t string) (proxyTarget, error) {
	scheme, rest, ok := strings.Cut(t, "://")
	if !ok {
		return proxyTarget{}, errNotAbsolute
	}
	switch strings.ToLower(scheme) {
	case "http":
	case "https":
		return proxyTarget{}, errHTTPSTarget
	default:
		return proxyTarget{}, errBadScheme
	}
	// A fragment is never sent on the wire (RFC 9110 §4.2.5); if one shows up
	// the client is broken or probing, so refuse rather than guess.
	if strings.Contains(rest, "#") {
		return proxyTarget{}, errBadAuthority
	}
	end := strings.IndexAny(rest, "/?")
	authority, path := rest, "/"
	if end >= 0 {
		authority, path = rest[:end], rest[end:]
		if path[0] == '?' { // "http://h?q" -> "/?q"
			path = "/" + path
		}
	}
	host, port, err := splitAuthority(authority)
	if err != nil {
		return proxyTarget{}, err
	}
	return proxyTarget{authority: authority, addr: net.JoinHostPort(host, port), path: path}, nil
}

// splitAuthority parses host[:port]. Userinfo ("user:pass@host") is refused:
// it is deprecated for http (RFC 9110 §4.2.4) and a classic way to make a
// URL look like it points somewhere it does not ("http://bank.com@evil/").
func splitAuthority(a string) (host, port string, err error) {
	if a == "" || strings.Contains(a, "@") {
		return "", "", errBadAuthority
	}
	host, port = a, "80"
	switch {
	case strings.HasPrefix(a, "["): // IPv6 literal: "[::1]" or "[::1]:8080"
		closeIdx := strings.Index(a, "]")
		if closeIdx < 0 {
			return "", "", errBadAuthority
		}
		host = a[1:closeIdx]
		tail := a[closeIdx+1:]
		if tail != "" {
			if !strings.HasPrefix(tail, ":") {
				return "", "", errBadAuthority
			}
			port = tail[1:]
		}
	case strings.Contains(a, ":"):
		host, port, _ = strings.Cut(a, ":")
	}
	if host == "" {
		return "", "", errBadAuthority
	}
	n, perr := strconv.Atoi(port)
	if perr != nil || n < 1 || n > 65535 || strings.ContainsAny(port, "+-") {
		return "", "", errBadAuthority
	}
	return host, port, nil
}
