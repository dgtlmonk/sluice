package engine

// FramingKind says how the end of a message body is found.
type FramingKind int

const (
	// FramingNone: the message has no body (length 0).
	FramingNone FramingKind = iota
	// FramingContentLength: exactly Framing.Length bytes follow the head.
	FramingContentLength
	// FramingChunked: the body is chunked-encoded; the decoder finds the end.
	FramingChunked
	// FramingCloseDelimited: responses only; the body runs until the server
	// closes the connection.
	FramingCloseDelimited
)

func (k FramingKind) String() string {
	switch k {
	case FramingNone:
		return "none"
	case FramingContentLength:
		return "content-length"
	case FramingChunked:
		return "chunked"
	case FramingCloseDelimited:
		return "close-delimited"
	}
	return "unknown"
}

// Framing is the body-length decision for one message. Length is only
// meaningful for FramingContentLength.
type Framing struct {
	Kind   FramingKind
	Length int64
}

// decideBodyFraming picks the body framing from the header fields alone.
// isResponse is false for requests, true for responses. The caller has
// already handled the cases where a response has no body regardless of its
// headers (reply to HEAD, 1xx, 204, 304), so this function never sees them.
func decideBodyFraming(h Headers, isResponse bool) (Framing, error) {
	/*
		RFC 9112 §6.3 "Message Body Length", as Sluice must apply it, in order:

		1. Transfer-Encoding AND Content-Length both present -> reject
		   (ErrCLAndTE). The RFC allows "TE wins", but SPEC.md says reject.
		   Smuggling: this is the classic CL.TE / TE.CL attack. The front end
		   frames by one header, the back end by the other, so the bytes left
		   over after the "short" body get parsed as a second, hidden request
		   on the shared upstream connection.

		2. Transfer-Encoding present and its final coding is "chunked"
		   -> FramingChunked. "Final" means the last element after splitting
		   every TE line on commas (transferCodings does that and lowercases).

		3. Transfer-Encoding present but final coding is NOT chunked
		   (e.g. "chunked, gzip", "gzip", "identity", "xchunked") -> reject
		   (ErrTENotChunked), for requests AND responses (SPEC.md is stricter
		   than the RFC, which would read a response like that until close).
		   Smuggling: if the length isn't chunk-framed, one hop may fall back
		   to Content-Length or close-delimited while another treats it as
		   chunked; obfuscated values like "chunked, identity" exist precisely
		   to make two parsers disagree.

		4. Content-Length present (no TE) -> parseContentLength over ALL its
		   values. Identical repeats ("5, 5" or two "5" lines) are one length;
		   differing values -> ErrConflictingCL; non-digits, signs, empty
		   -> ErrInvalidCL. Length 0 is still FramingContentLength{Length: 0}.
		   Smuggling: with "CL: 5" and "CL: 50", a hop that takes the first and
		   one that takes the last disagree on where the body ends.

		5. Neither header:
		   - request  -> FramingNone (a request body is never close-delimited;
		     the client can't half-close to end it and still read the reply).
		   - response -> FramingCloseDelimited (read until the server closes).
	*/
	hasTE := h.Has("Transfer-Encoding")
	hasCL := h.Has("Content-Length")

	// Rule 1: two length signals = two possible readings. Refuse both.
	if hasTE && hasCL {
		return Framing{}, ErrCLAndTE
	}

	// Rules 2-3: only a TE list ending in "chunked" is accepted. An empty
	// TE value (no codings at all) counts as "not chunked" too.
	if hasTE {
		codings, err := transferCodings(h)
		if err != nil {
			return Framing{}, err
		}
		if len(codings) == 0 || codings[len(codings)-1] != "chunked" {
			return Framing{}, ErrTENotChunked
		}
		// RFC 9112 §6.1: a sender MUST NOT apply chunked more than once, so
		// "chunked" may appear only as the final coding. "chunked, chunked"
		// (or "chunked" on one TE line and again on a later one) is invalid:
		// a hop that de-chunks once would forward still-chunked bytes that
		// the next hop frames differently.
		for _, c := range codings[:len(codings)-1] {
			if c == "chunked" {
				return Framing{}, ErrTEChunkedTwice
			}
		}
		return Framing{Kind: FramingChunked}, nil
	}

	// Rule 4: every CL value must parse and agree.
	if hasCL {
		n, err := parseContentLength(h.Values("Content-Length"))
		if err != nil {
			return Framing{}, err
		}
		return Framing{Kind: FramingContentLength, Length: n}, nil
	}

	// Rule 5: no length signal at all.
	if isResponse {
		return Framing{Kind: FramingCloseDelimited}, nil
	}
	return Framing{Kind: FramingNone}, nil
}
