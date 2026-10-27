/**
 * Inspector parsing: turns one captured request/response into the name/value
 * rows the Inspector panel shows (query and body parameters, cookies,
 * headers, Set-Cookie attributes). Pure module: no React, no store, no Wails
 * types, so the Repeater can reuse it on text the user is editing.
 *
 * Input is the detail pane's MessageView text, which Go has already made
 * display-safe (escapeText in detail.go: control characters shown as `\x..`,
 * invisible ones as `\u{..}`, CRLF turned into LF). Decoding can bring hidden
 * characters back (`%0d%0a` is a CRLF, `%00` a NUL, `%E2%80%AE` a
 * right-to-left override), so every decoded value goes through visible()
 * again before it is shown. The output is still untrusted text: render it as
 * text nodes only, never as HTML.
 *
 * Rules a tester relies on:
 *   - Duplicates are kept as separate rows, in wire order. `id=1&id=2` is
 *     HTTP parameter pollution: front end and back end may each read a
 *     different one. JSON duplicate keys are kept too (JSON.parse would
 *     silently keep only the last).
 *   - Nothing is dropped for being odd: a parameter with no `=`, a bad `%`
 *     escape, a cookie without a value all show up as rows.
 *   - Where two parsers could read the same bytes differently (multipart
 *     names, header names with spaces), the row says so.
 */

import { matches, type Matcher } from '../view/search'

/** One header line, as the detail pane receives it (main.HeaderField). */
export type HeaderLine = { readonly name: string; readonly value: string; readonly malformed: boolean }

/** One side of an exchange: the fields of main.MessageView the Inspector reads. */
export type MessageInput = {
  readonly captured: boolean
  readonly startLine: string
  readonly headers: readonly HeaderLine[]
  readonly body: string
  /** 'text' or 'hex' (a binary body, shown as a hex dump: nothing to parse). */
  readonly bodyEncoding: string
  /** The body text is only the first part of the stored body. */
  readonly bodyViewTruncated: boolean
}

/** Facts about the exchange that are not in the message text. */
export type ExchangeContext = {
  readonly scheme: string
  readonly host: string
  readonly port: number
  /** Why the connection was tunnelled raw (not decrypted); '' when it was decrypted. */
  readonly tunnel: string
  /** The client's JA4 TLS fingerprint; '' for plain HTTP or when unknown. */
  readonly ja4: string
}

export type Tone = 'warn' | 'info'

/** A short marker on a row, e.g. "no HttpOnly". `why` is the hover explanation. */
export type Flag = { readonly tone: Tone; readonly label: string; readonly why: string }

export type Row = {
  /** Decoded and display-safe. */
  readonly name: string
  /** The name as captured (already display-safe). */
  readonly rawName: string
  /** Decoded and display-safe. */
  readonly value: string
  /** As captured (already display-safe). Equal to value when nothing was decoded. */
  readonly raw: string
  /** How many rows in the same section share this name (1 = unique). */
  readonly dupes: number
  /** Set when dupes > 1: what a repeat of this name means in this section. */
  readonly dupe?: Flag
  readonly flags: readonly Flag[]
  /** Extra detail under the value, e.g. a cookie's attributes. */
  readonly detail?: string
}

/** A row before duplicates are counted. */
type Draft = Omit<Row, 'dupes' | 'dupe'>

export type SectionId = 'attributes' | 'query' | 'body' | 'reqCookies' | 'reqHeaders' | 'resHeaders' | 'resCookies'

export type Section = {
  readonly id: SectionId
  readonly title: string
  readonly rows: readonly Row[]
  /** Why rows are missing or partial (binary body, chunked, not captured), or what is odd about them. */
  readonly note?: string
}

export type Protocol = 'HTTP/1' | 'HTTP/2' | 'unknown'

export type ProtocolInfo = {
  /** The HTTP version the exchange used, as far as Sluice can tell. */
  readonly used: Protocol
  /** Where `used` comes from, or what it hides. */
  readonly note: string
  readonly flag?: Flag
}

export type Inspection = {
  readonly protocol: ProtocolInfo
  readonly sections: readonly Section[]
}

// ---------------------------------------------------------------------------
// Text helpers
// ---------------------------------------------------------------------------

// Cc: C0 controls, DEL, C1 controls. Cf: invisible formatting characters
// (bidi overrides, zero-width joiners). U+2028/2029: line/paragraph separators.
const HIDDEN = /[\p{Cc}\p{Cf}\u2028\u2029]/gu
const IS_HIDDEN = /^[\p{Cc}\p{Cf}\u2028\u2029]$/u

/**
 * Makes every control or invisible character visible, like escapeText in
 * detail.go, except that tab and newline are escaped too: inside a single
 * value a decoded line break is a finding (header or log injection), not
 * layout.
 */
export function visible(s: string): string {
  return s.replace(HIDDEN, (c) => {
    const code = c.codePointAt(0) ?? 0
    return code < 0x20 || code === 0x7f ? `\\x${hex2(code)}` : `\\u{${code.toString(16).padStart(4, '0')}}`
  })
}

const hex2 = (n: number) => n.toString(16).padStart(2, '0')

const utf8 = new TextEncoder()
// ignoreBOM keeps a leading U+FEFF: a decoder that strips it would hide
// `%EF%BB%BFadmin` behind a clean-looking "admin".
const strictUtf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })

const isHexCode = (c: number) => (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66)

/**
 * Percent-decodes leniently. Valid `%XX` escapes become bytes; a stray `%`
 * stays as it is (decodeURIComponent would throw and lose the whole value).
 * With plusAsSpace (form encoding, used by query strings and form bodies),
 * `+` means a space. Bytes that are not valid UTF-8 are shown as `\xNN`
 * instead of being replaced by U+FFFD, so an overlong or truncated sequence
 * (a classic filter bypass) stays visible; the valid text around them is
 * still decoded.
 *
 * Linear time: literal text between escapes is encoded a run at a time into
 * one buffer, not a character at a time.
 */
export function percentDecode(s: string, plusAsSpace: boolean): string {
  if (!s.includes('%') && !(plusAsSpace && s.includes('+'))) return s
  // Worst case: every UTF-16 unit becomes 3 bytes (a surrogate pair, 2 units,
  // becomes 4); an escape's 3 characters become 1 byte. So 3x always fits.
  const out = new Uint8Array(s.length * 3)
  let n = 0
  let runStart = 0 // start of the literal text not yet copied into out
  const flush = (end: number) => {
    if (end > runStart) n += utf8.encodeInto(s.slice(runStart, end), out.subarray(n)).written
  }
  for (let i = 0; i < s.length; ) {
    const c = s.charCodeAt(i)
    if (c === 0x25 /* % */ && isHexCode(s.charCodeAt(i + 1)) && isHexCode(s.charCodeAt(i + 2))) {
      flush(i)
      out[n++] = parseInt(s.slice(i + 1, i + 3), 16)
      i += 3
      runStart = i
    } else if (c === 0x2b /* + */ && plusAsSpace) {
      flush(i)
      out[n++] = 0x20
      i++
      runStart = i
    } else {
      i++
    }
  }
  flush(s.length)
  return decodeUtf8Lenient(out.subarray(0, n))
}

/**
 * Decodes UTF-8, showing each byte that is not part of a valid sequence as
 * `\xNN`. "café%FF" becomes "café\xff", not "caf\xc3\xa9\xff".
 */
export function decodeUtf8Lenient(b: Uint8Array): string {
  try {
    return strictUtf8.decode(b)
  } catch {
    // fall through to the byte-by-byte walk
  }
  let out = ''
  let start = 0 // start of the valid run not yet decoded
  for (let i = 0; i < b.length; ) {
    const len = utf8SequenceLength(b, i)
    if (len > 0) {
      i += len
      continue
    }
    out += `${strictUtf8.decode(b.subarray(start, i))}\\x${hex2(b[i])}`
    i++
    start = i
  }
  return out + strictUtf8.decode(b.subarray(start))
}

/**
 * Length of the valid UTF-8 sequence starting at b[i], or 0 if there is none.
 * The ranges are the Unicode well-formed table (Unicode 15 §3.9, Table 3-7):
 * they reject overlong forms (C0, C1, E0 80..9F, F0 80..8F), UTF-16
 * surrogates (ED A0..BF) and code points past U+10FFFF (F4 90.., F5..FF).
 */
function utf8SequenceLength(b: Uint8Array, i: number): number {
  const x = b[i]
  if (x < 0x80) return 1
  const cont = (k: number, lo = 0x80, hi = 0xbf) => i + k < b.length && b[i + k] >= lo && b[i + k] <= hi
  if (x >= 0xc2 && x <= 0xdf) return cont(1) ? 2 : 0
  if (x >= 0xe0 && x <= 0xef) return cont(1, x === 0xe0 ? 0xa0 : 0x80, x === 0xed ? 0x9f : 0xbf) && cont(2) ? 3 : 0
  if (x >= 0xf0 && x <= 0xf4) return cont(1, x === 0xf0 ? 0x90 : 0x80, x === 0xf4 ? 0x8f : 0xbf) && cont(2) && cont(3) ? 4 : 0
  return 0
}

/** Header values for `name` (case-insensitive, surrounding spaces ignored), in wire order. */
export function headerValues(headers: readonly HeaderLine[], name: string): string[] {
  const want = name.toLowerCase()
  return headers.filter((h) => !h.malformed && h.name.trim().toLowerCase() === want).map((h) => h.value)
}

/** The media type of a Content-Type value, lower-cased, without parameters. */
export function mediaType(contentType: string): string {
  return contentType.split(';', 1)[0].trim().toLowerCase()
}

/**
 * Splits a header value with parameters (`form-data; name="a"; filename="b;c"`)
 * into its leading value and its parameters, in order, duplicates kept.
 * Quoted strings are read as one token, so a `;` or `name=` inside quotes
 * is part of the value, not a new parameter (RFC 9110 §5.6.6). Parameter
 * names are lower-cased; values are unquoted.
 */
export function parseParams(header: string): { value: string; params: (readonly [string, string])[] } {
  const params: [string, string][] = []
  let i = header.indexOf(';')
  const value = (i < 0 ? header : header.slice(0, i)).trim()
  if (i < 0) return { value, params }
  while (i < header.length) {
    i++ // past ';'
    const nameEnd = indexOfAny(header, '=;', i)
    const name = header.slice(i, nameEnd).trim().toLowerCase()
    i = nameEnd
    let v = ''
    if (header[i] === '=') {
      i++
      while (header[i] === ' ' || header[i] === '\t') i++
      if (header[i] === '"') {
        // quoted-string: ends at the first unescaped quote; `\x` means x.
        i++
        while (i < header.length && header[i] !== '"') {
          if (header[i] === '\\' && i + 1 < header.length) i++
          v += header[i]
          i++
        }
        i = indexOfAny(header, ';', i) // skip the closing quote and any junk after it
      } else {
        const end = indexOfAny(header, ';', i)
        v = header.slice(i, end).trim()
        i = end
      }
    }
    if (name !== '') params.push([name, v])
  }
  return { value, params }
}

/** Index of the first of `chars` in s at or after `from`, or s.length. */
function indexOfAny(s: string, chars: string, from: number): number {
  for (let i = from; i < s.length; i++) if (chars.includes(s[i])) return i
  return s.length
}

/** One parameter of a header value (e.g. a Content-Type boundary), unquoted; '' if absent. */
export function contentTypeParam(contentType: string, param: string): string {
  const want = param.toLowerCase()
  return parseParams(contentType).params.find(([k]) => k === want)?.[1] ?? ''
}

// ---------------------------------------------------------------------------
// Duplicates
// ---------------------------------------------------------------------------

/**
 * How a section treats repeated names. Whether a repeat is a finding depends
 * on where it is: a second `id=` in a query is parameter pollution, a second
 * Set-Cookie header is how every site sets two cookies.
 */
type DupePolicy = {
  /** The name two rows must share to count as repeats. */
  readonly key: (name: string) => string
  readonly flag: (key: string, count: number) => Flag
}

const exactName = (n: string) => n
// Header names are case-insensitive (RFC 9110 §5.1). Spaces are trimmed so
// that "Host" and "Host " (space before the colon) count as the same header:
// some servers read them as one, others reject or ignore the second.
const headerName = (n: string) => n.trim().toLowerCase()

const POLLUTION: DupePolicy = {
  key: exactName,
  flag: (_, n) => ({
    tone: 'warn',
    label: `×${n}`,
    why: `Sent ${n} times. Front end and back end may each read a different copy (HTTP parameter pollution).`,
  }),
}

const REQUEST_COOKIE_DUPES: DupePolicy = {
  key: exactName,
  flag: (_, n) => ({
    tone: 'warn',
    label: `×${n}`,
    why: `Cookie sent ${n} times (set for different paths or domains). Servers differ on which copy they read, which is how cookie tossing works.`,
  }),
}

/** Request headers where two copies let a proxy and a server disagree. */
const SINGLE_REQUEST_HEADERS = new Set([
  'host',
  'content-length',
  'transfer-encoding',
  'content-type',
  'authorization',
  'cookie',
  'origin',
  'forwarded',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-real-ip',
])

const REQUEST_HEADER_DUPES: DupePolicy = {
  key: headerName,
  flag: (k, n) =>
    SINGLE_REQUEST_HEADERS.has(k)
      ? {
          tone: 'warn',
          label: `×${n}`,
          why: `Sent ${n} times. A proxy and the server may each use a different copy (request smuggling, host or auth confusion).`,
        }
      : { tone: 'info', label: `×${n}`, why: `Sent ${n} times. Normal for list headers; a proxy may merge the copies or keep one.` },
}

/** Response headers that must appear once; a repeat is a desync or a policy that may be ignored. */
const SINGLE_RESPONSE_HEADERS = new Set([
  'content-length',
  'transfer-encoding',
  'content-type',
  'content-encoding',
  'location',
  'access-control-allow-origin',
  'access-control-allow-credentials',
  'strict-transport-security',
  'x-frame-options',
])

const RESPONSE_HEADER_DUPES: DupePolicy = {
  key: headerName,
  flag: (k, n) =>
    SINGLE_RESPONSE_HEADERS.has(k)
      ? {
          tone: 'warn',
          label: `×${n}`,
          why: `Sent ${n} times, but this header must appear once. Clients may pick different copies, reject the response, or ignore the policy.`,
        }
      : { tone: 'info', label: `×${n}`, why: `Sent ${n} times. Normal for list headers such as Set-Cookie, Vary and Link.` },
}

const SET_COOKIE_DUPES: DupePolicy = {
  key: exactName,
  flag: (_, n) => ({
    tone: 'info',
    label: `×${n}`,
    why: `Set ${n} times in this response. With the same Path and Domain the last one wins; otherwise the browser keeps both.`,
  }),
}

/** Fills in `dupes` (how many rows share each row's name) and, with a policy, `dupe`. */
function withDupes(rows: readonly Draft[], policy?: DupePolicy): Row[] {
  const key = policy?.key ?? exactName
  const counts = new Map<string, number>()
  for (const r of rows) counts.set(key(r.name), (counts.get(key(r.name)) ?? 0) + 1)
  return rows.map((r) => {
    const k = key(r.name)
    const dupes = counts.get(k) ?? 1
    return dupes > 1 && policy ? { ...r, dupes, dupe: policy.flag(k, dupes) } : { ...r, dupes }
  })
}

const plain = (name: string, value: string, flags: readonly Flag[] = []): Draft => ({ name, rawName: name, value, raw: value, flags })

// ---------------------------------------------------------------------------
// Start line and request target
// ---------------------------------------------------------------------------

export type RequestLine = { readonly method: string; readonly target: string; readonly version: string }

/**
 * Splits "GET /a?b=1 HTTP/1.1" leniently; missing parts are ''. The method
 * is the first token and the version the last, so a target with a space in
 * it ("GET /a b HTTP/1.1", invalid but seen in attacks) stays whole.
 */
export function parseRequestLine(line: string): RequestLine {
  const t = line.trim()
  const first = t.indexOf(' ')
  if (first < 0) return { method: t, target: '', version: '' }
  const last = t.lastIndexOf(' ')
  const middle = t.slice(first, last).trim()
  // Two tokens ("GET /a", HTTP/0.9 style): the second is the target.
  if (middle === '') return { method: t.slice(0, first), target: t.slice(last + 1), version: '' }
  return { method: t.slice(0, first), target: middle, version: t.slice(last + 1) }
}

/**
 * Maps an HTTP version token to the protocol family. A status line starts
 * with the version, a request line ends with it; pass just the token.
 */
export function protocolOf(version: string): Protocol {
  if (/^HTTP\/1\.\d$/.test(version)) return 'HTTP/1'
  if (/^HTTP\/2(\.0)?$/.test(version)) return 'HTTP/2'
  return 'unknown'
}

export type Target = { readonly path: string; readonly query: string | null; readonly fragment: string | null }

/**
 * Splits a request target into path, query and fragment. Handles
 * origin-form ("/a?b"), absolute-form ("http://h/a?b", what a client sends
 * to a plain HTTP proxy) and authority-form ("host:443", CONNECT; pass
 * isConnect), which has no path. Clients never send a fragment (`#...`);
 * one in a target is split off so it does not end up in the last query
 * value, and reported.
 */
export function splitTarget(target: string, isConnect = false): Target {
  if (isConnect) return { path: '', query: null, fragment: null }
  let t = target
  let fragment: string | null = null
  const hash = t.indexOf('#')
  if (hash >= 0) {
    fragment = t.slice(hash + 1)
    t = t.slice(0, hash)
  }
  const abs = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^/?]*/.exec(t)
  if (abs) t = t.slice(abs[0].length)
  if (abs && !t.startsWith('/')) t = `/${t}` // "http://h" and "http://h?q" mean path "/"
  const q = t.indexOf('?')
  return q < 0 ? { path: t, query: null, fragment } : { path: t.slice(0, q), query: t.slice(q + 1), fragment }
}

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

/**
 * Parses `a=1&b=x%20y&a=2` (query string or form body) into rows, in order,
 * duplicates kept. Empty segments (`a=1&&b=2`) are skipped; a segment with
 * no `=` is a name with an empty value.
 */
export function parseFormEncoded(s: string): Row[] {
  const rows: Draft[] = []
  for (const seg of s.split('&')) {
    if (seg === '') continue
    const eq = seg.indexOf('=')
    const rawName = eq < 0 ? seg : seg.slice(0, eq)
    const rawValue = eq < 0 ? '' : seg.slice(eq + 1)
    rows.push({
      name: visible(percentDecode(rawName, true)),
      rawName,
      value: visible(percentDecode(rawValue, true)),
      raw: rawValue,
      flags: [],
    })
  }
  return withDupes(rows, POLLUTION)
}

/**
 * Turns Go's display escapes inside JSON strings back into JSON escapes, so
 * a body that was valid JSON on the wire still parses. escapeText shows a
 * literal U+202E as `\u{202e}` and a DEL as `\x7f`; both are legal raw in a
 * JSON string, but `\u{` and `\x` are not JSON escapes. Only the characters
 * escapeText escapes are converted. Raw C0 controls stay as `\xNN`: they are
 * not allowed in JSON strings, so that body was never valid JSON.
 */
export function jsonFromDisplay(text: string): string {
  if (!text.includes('\\u{') && !text.includes('\\x7f')) return text
  let out = ''
  let inString = false
  for (let i = 0; i < text.length; i++) {
    const c = text[i]
    if (!inString) {
      if (c === '"') inString = true
      out += c
      continue
    }
    if (c === '"') inString = false
    if (c !== '\\') {
      out += c
      continue
    }
    const goEscape = /^\\u\{([0-9a-f]{4,6})\}/.exec(text.slice(i, i + 10))
    const cp = goEscape ? parseInt(goEscape[1], 16) : -1
    if (goEscape && cp <= 0x10ffff && IS_HIDDEN.test(String.fromCodePoint(cp))) {
      out += jsonEscape(cp)
      i += goEscape[0].length - 1
    } else if (text.startsWith('\\x7f', i)) {
      out += '\\u007f'
      i += 3
    } else {
      out += c + (text[i + 1] ?? '') // an ordinary JSON escape: copy it whole
      i++
    }
  }
  return out
}

/** A code point as a JSON `\uXXXX` escape (a surrogate pair above U+FFFF). */
function jsonEscape(cp: number): string {
  const units = String.fromCodePoint(cp)
  let out = ''
  for (let k = 0; k < units.length; k++) out += `\\u${units.charCodeAt(k).toString(16).padStart(4, '0')}`
  return out
}

/** Removes whitespace outside strings: a pretty-printed nested value on one line. */
function compactJson(s: string): string {
  let out = ''
  let inString = false
  for (let i = 0; i < s.length; i++) {
    const c = s[i]
    if (inString) {
      out += c
      if (c === '\\') out += s[++i] ?? ''
      else if (c === '"') inString = false
    } else if (c === '"') {
      inString = true
      out += c
    } else if (!' \t\n\r'.includes(c)) {
      out += c
    }
  }
  return out
}

/**
 * Lists the top-level members of a JSON body: object keys (duplicates kept,
 * in order) or array indexes. String values are decoded (raw keeps the
 * quoted form); objects and arrays are shown compacted onto one line, so a
 * line break left in a value is a real one inside a string, not layout.
 * Returns null when the text is not valid JSON or is a bare scalar.
 */
export function parseJsonTopLevel(text: string): Row[] | null {
  try {
    JSON.parse(jsonFromDisplay(text)) // validity check; the scan below keeps what parse loses
  } catch {
    return null
  }
  // The scan runs on the display text, so raw slices are what was captured.
  // Go's escapes only ever sit inside strings, where they do not change the
  // structure, so the text is as well formed as the JSON it came from.
  const s = text.trim()
  if (s[0] !== '{' && s[0] !== '[') return null
  const isObject = s[0] === '{'
  const decode = (slice: string) => JSON.parse(jsonFromDisplay(slice)) as string
  const rows: Draft[] = []
  let i = skipWs(s, 1)
  for (let index = 0; i < s.length && s[i] !== '}' && s[i] !== ']'; index++) {
    let name = `[${index}]`
    let rawName = name
    if (isObject) {
      const keyEnd = endOfJsonValue(s, i)
      rawName = s.slice(i, keyEnd)
      name = visible(decode(rawName))
      i = skipWs(s, keyEnd) + 1 // past ':'
      i = skipWs(s, i)
    }
    const end = endOfJsonValue(s, i)
    const raw = s.slice(i, end)
    rows.push({
      name,
      rawName,
      value: visible(raw.startsWith('"') ? decode(raw) : compactJson(raw)),
      raw,
      flags: [],
    })
    i = skipWs(s, end)
    if (s[i] === ',') i = skipWs(s, i + 1)
  }
  return withDupes(rows, POLLUTION)
}

const skipWs = (s: string, i: number) => {
  while (i < s.length && ' \t\n\r'.includes(s[i])) i++
  return i
}

/**
 * Index just past the JSON value starting at s[i]. Only called on text that
 * JSON.parse accepted, so it can assume the value is well formed: strings
 * end at an unescaped quote, containers at the matching bracket.
 */
function endOfJsonValue(s: string, i: number): number {
  let depth = 0
  let inString = false
  for (let j = i; j < s.length; j++) {
    const c = s[j]
    if (inString) {
      if (c === '\\') j++
      else if (c === '"') {
        inString = false
        if (depth === 0) return j + 1
      }
      continue
    }
    if (c === '"') inString = true
    else if (c === '{' || c === '[') depth++
    else if (c === '}' || c === ']') {
      if (depth === 0) return j // end of the enclosing container: a scalar ended here
      depth--
      if (depth === 0) return j + 1
    } else if (depth === 0 && (c === ',' || c === ' ' || c === '\t' || c === '\n' || c === '\r')) return j
  }
  return s.length
}

/**
 * Lists multipart/form-data fields by name (RFC 7578, framing from RFC 2046
 * §5.1.1). A delimiter is a whole line: "--boundary" (or "--boundary--" to
 * close), optionally followed by spaces. "--boundary" in the middle of a
 * line is content, so a value cannot fabricate a part. The body text has
 * CRLF turned into LF already, so lines are split on LF. File parts show the
 * file name and type instead of their content.
 */
export function parseMultipart(body: string, boundary: string): Row[] {
  const delimiter = `--${boundary}`
  const parts: string[][] = []
  let current: string[] | null = null // null: preamble, before the first delimiter
  for (const line of body.split('\n')) {
    const t = line.replace(/[ \t]+$/, '') // transport padding after a delimiter
    if (t === delimiter || t === `${delimiter}--`) {
      if (current) parts.push(current)
      current = t === delimiter ? [] : null
      if (current === null) break // close delimiter: the rest is the epilogue
      continue
    }
    current?.push(line)
  }
  if (current) parts.push(current) // no close delimiter (body truncated in view)

  const rows: Draft[] = []
  for (const lines of parts) {
    const blank = lines.indexOf('')
    const head = blank < 0 ? lines : lines.slice(0, blank)
    const content = blank < 0 ? '' : lines.slice(blank + 1).join('\n')
    const headers = head.map((l): HeaderLine => {
      const c = l.indexOf(':')
      return { name: c < 0 ? '' : l.slice(0, c).trim(), value: c < 0 ? l : l.slice(c + 1).trim(), malformed: c < 0 }
    })
    rows.push(multipartRow(headers, content))
  }
  return withDupes(rows, POLLUTION)
}

/** One multipart part as a row, flagging what two parsers may read differently. */
function multipartRow(headers: readonly HeaderLine[], content: string): Draft {
  const { params } = parseParams(headerValues(headers, 'content-disposition')[0] ?? '')
  const all = (k: string) => params.filter(([n]) => n === k).map(([, v]) => v)
  const names = all('name')
  const filenames = all('filename')
  // RFC 5987 ext-value: charset'language'percent-encoded, e.g. UTF-8''a%20b.txt
  const extFilenames = all('filename*').map((v) => percentDecode(v.replace(/^[^']*'[^']*'/, ''), false))
  const flags: Flag[] = []
  if (names.length > 1)
    flags.push({
      tone: 'warn',
      label: `name ×${names.length}`,
      why: `Content-Disposition names this field ${names.length} times (${names.map((n) => `"${n}"`).join(', ')}). Parsers differ on which one they use, so a WAF and the app can see different fields.`,
    })
  if (extFilenames.length > 0)
    flags.push({
      tone: 'warn',
      label: 'filename*',
      why: 'RFC 7578 forbids filename* in form data, yet some servers prefer it to filename. When both are sent they can name different files (upload filter bypass).',
    })
  const name = names[0] ?? '(no name)'
  const draft = { name: visible(name), rawName: visible(name), flags }
  if (filenames.length === 0 && extFilenames.length === 0) return { ...draft, value: visible(content), raw: content }
  const shown = [...filenames.map((f) => `"${f}"`), ...extFilenames.map((f) => `filename*="${f}"`)].join(' / ')
  const type = headerValues(headers, 'content-type')[0] ?? 'no type'
  return { ...draft, value: visible(`(file) ${shown} · ${type} · ${content.length.toLocaleString()} chars`), raw: content }
}

/** Request body as form fields when it looks like `a=1&b=2` and nothing else. */
const FORM_SHAPE = /^[^\s&=]+=[^\s&]*(?:&[^\s&=]+(?:=[^\s&]*)?)*&?$/

// ---------------------------------------------------------------------------
// Cookies
// ---------------------------------------------------------------------------

/**
 * Splits Cookie header values ("a=1; b=2") into rows. Several Cookie lines
 * are all read, in order. Cookie values are not URL-decoded by browsers, but
 * apps often store encoded data in them, so the decoded form is shown and
 * raw stays available.
 */
export function parseCookieHeader(values: readonly string[]): Row[] {
  const rows: Draft[] = []
  for (const v of values) {
    for (const pair of v.split(';')) {
      const p = pair.trim()
      if (p === '') continue
      const eq = p.indexOf('=')
      const name = eq < 0 ? '' : p.slice(0, eq).trim()
      const raw = eq < 0 ? p : p.slice(eq + 1).trim()
      rows.push({ name, rawName: name, value: visible(percentDecode(raw, false)), raw, flags: [] })
    }
  }
  return withDupes(rows, REQUEST_COOKIE_DUPES)
}

export type SetCookie = {
  readonly name: string
  readonly value: string
  /** Attributes in order as sent, e.g. [["Path", "/"], ["Secure", ""]]. */
  readonly attrs: readonly (readonly [string, string])[]
  readonly secure: boolean
  readonly httpOnly: boolean
  /** As sent ("Lax", "Strict", "None", or something invalid); null if absent. */
  readonly sameSite: string | null
  readonly path: string | null
  readonly domain: string | null
  readonly expires: string | null
  readonly maxAge: string | null
}

/** Parses one Set-Cookie value (RFC 6265 §5.2, lenient). */
export function parseSetCookie(header: string): SetCookie {
  const [pair, ...attrParts] = header.split(';')
  const eq = pair.indexOf('=')
  const attrs = attrParts
    .map((a) => a.trim())
    .filter((a) => a !== '')
    .map((a): [string, string] => {
      const e = a.indexOf('=')
      return e < 0 ? [a, ''] : [a.slice(0, e).trim(), a.slice(e + 1).trim()]
    })
  // RFC 6265 §5.2: attribute names are case-insensitive; the last one wins.
  const last = (n: string) => {
    const hit = attrs.filter(([k]) => k.toLowerCase() === n)
    return hit.length ? hit[hit.length - 1] : null
  }
  return {
    name: eq < 0 ? '' : pair.slice(0, eq).trim(),
    value: eq < 0 ? pair.trim() : pair.slice(eq + 1).trim(),
    attrs,
    secure: last('secure') !== null,
    httpOnly: last('httponly') !== null,
    sameSite: last('samesite')?.[1] ?? null,
    path: last('path')?.[1] ?? null,
    domain: last('domain')?.[1] ?? null,
    expires: last('expires')?.[1] ?? null,
    maxAge: last('max-age')?.[1] ?? null,
  }
}

/**
 * True when the Set-Cookie deletes the cookie (Max-Age <= 0, or Expires in
 * the past). Missing flags on a deletion are noise, so they are not flagged.
 */
export function deletesCookie(c: SetCookie, now: number): boolean {
  if (c.maxAge !== null && /^-?\d+$/.test(c.maxAge)) return Number(c.maxAge) <= 0
  if (c.expires !== null) {
    const t = Date.parse(c.expires)
    return !Number.isNaN(t) && t <= now
  }
  return false
}

/**
 * What an AppSec tester checks on every Set-Cookie. These are prompts to
 * look, not verdicts: a cookie the page's JavaScript must read cannot be
 * HttpOnly, and that can be fine. `scheme` is the scheme the response came
 * over: an http:// origin cannot set Secure cookies at all, so there the
 * finding is the plain-HTTP transport, not the missing flag.
 */
export function cookieFlags(c: SetCookie, now: number, scheme: string): Flag[] {
  if (deletesCookie(c, now)) return [{ tone: 'info', label: 'deletes cookie', why: 'Max-Age <= 0 or Expires in the past: this removes the cookie.' }]
  const flags: Flag[] = []
  const overHttp = scheme === 'http'
  if (overHttp && c.secure)
    flags.push({ tone: 'warn', label: 'Secure over HTTP', why: 'Browsers ignore a Secure cookie set by a plain-HTTP response (localhost aside): this cookie is likely dropped.' })
  else if (overHttp)
    flags.push({ tone: 'warn', label: 'set over HTTP', why: 'Set over plain HTTP: anyone on the network can read it. Secure cannot help until the site moves to HTTPS.' })
  else if (!c.secure)
    flags.push({ tone: 'warn', label: 'no Secure', why: 'Without Secure the browser also sends this cookie over plain HTTP, where anyone on the network can read it.' })
  if (!c.httpOnly)
    flags.push({ tone: 'warn', label: 'no HttpOnly', why: 'Without HttpOnly, page JavaScript (and so any XSS) can read this cookie via document.cookie.' })
  const ss = c.sameSite?.toLowerCase() ?? null
  if (ss === null)
    flags.push({ tone: 'warn', label: 'no SameSite', why: 'No SameSite: Chrome treats it as Lax, other browsers may send it on cross-site requests (CSRF).' })
  else if (ss !== 'lax' && ss !== 'strict' && ss !== 'none')
    flags.push({ tone: 'warn', label: `SameSite=${c.sameSite}?`, why: 'Unknown SameSite value: browsers ignore it and fall back to their default.' })
  else if (ss === 'none' && !c.secure)
    flags.push({ tone: 'warn', label: 'SameSite=None without Secure', why: 'Browsers reject SameSite=None cookies that are not also Secure.' })
  // Prefixes are matched case-insensitively (RFC 6265bis §4.1.3), so
  // "__HOST-sid" gets the same rules as "__Host-sid".
  const lower = c.name.toLowerCase()
  if (lower.startsWith('__host-') && (!c.secure || c.path !== '/' || c.domain !== null))
    flags.push({ tone: 'warn', label: '__Host- rules broken', why: '__Host- cookies must be Secure, have Path=/ and no Domain; browsers reject this one.' })
  else if (lower.startsWith('__secure-') && !c.secure)
    flags.push({ tone: 'warn', label: '__Secure- without Secure', why: '__Secure- cookies must be Secure; browsers reject this one.' })
  if (c.domain !== null)
    flags.push({ tone: 'info', label: `Domain=${c.domain}`, why: 'A Domain attribute shares the cookie with every subdomain; any of them can read or overwrite it.' })
  return flags
}

/** Set-Cookie headers as rows: name, value, attributes as detail, flags. */
export function parseSetCookies(values: readonly string[], now: number, scheme: string): Row[] {
  return withDupes(
    values.map((v) => {
      const c = parseSetCookie(v)
      return {
        name: c.name,
        rawName: c.name,
        value: visible(percentDecode(c.value, false)),
        raw: c.value,
        flags: cookieFlags(c, now, scheme),
        detail: c.attrs.map(([k, val]) => (val === '' ? k : `${k}=${val}`)).join('; ') || '(no attributes)',
      }
    }),
    SET_COOKIE_DUPES,
  )
}

// ---------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------

/** Tunnel reasons that mean the traffic inside was HTTP/2. Must match tlspolicy.go. */
const H2_TUNNEL_REASONS = ['client offers only h2', 'host refuses http/1.1']

/**
 * The client's first ALPN choice, from its JA4 fingerprint. JA4's first
 * section ends with the first and last character of the first ALPN value
 * ("t13d1516h2_..." -> "h2"; "h1" is http/1.1, "00" is none).
 */
export function ja4FirstAlpn(ja4: string): string | null {
  const a = ja4.split('_', 1)[0]
  return a.length === 10 ? a.slice(8) : null
}

/**
 * Which HTTP version the exchange used. A raw tunnel's request line is the
 * CONNECT, which is always HTTP/1.1, so for tunnels the tunnel reason says
 * what was inside. For decrypted HTTPS the request line is right, but it is
 * HTTP/1.1 because Sluice only offers http/1.1 in ALPN (mitm.go); when the
 * client's JA4 shows it wanted h2, that downgrade is reported.
 */
export function protocolInfo(req: MessageInput, res: MessageInput, version: string, ctx: ExchangeContext): ProtocolInfo {
  if (ctx.tunnel) {
    return H2_TUNNEL_REASONS.includes(ctx.tunnel)
      ? { used: 'HTTP/2', note: 'Inside a raw tunnel (not decrypted); the CONNECT before it was HTTP/1.1.' }
      : { used: 'unknown', note: 'Tunnelled raw: the traffic inside was not decrypted.' }
  }
  const fromResponse = !req.captured
  const used = protocolOf(fromResponse ? (res.startLine.trim().split(' ', 1)[0] ?? '') : version)
  const note = fromResponse ? 'From the status line (request not captured).' : 'From the request line.'
  if (ctx.scheme === 'https' && used === 'HTTP/1' && ja4FirstAlpn(ctx.ja4) === 'h2')
    return {
      used,
      note,
      flag: {
        tone: 'info',
        label: 'downgraded from h2',
        why: 'The client offered h2 first (its JA4 says so), but Sluice answers ALPN with http/1.1 only, so both legs ran HTTP/1.1. Bugs that only exist over HTTP/2 (h2 request smuggling) will not show here.',
      },
    }
  return { used, note }
}

// ---------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------

type BodyResult = { readonly rows: Row[]; readonly note?: string }

/** Request body parameters by Content-Type, or a note saying why there are none. */
export function bodyParams(m: MessageInput): BodyResult {
  const ct = headerValues(m.headers, 'content-type')[0] ?? ''
  const type = mediaType(ct)
  if (m.body === '') return { rows: [] }
  if (m.bodyEncoding !== 'text') return { rows: [], note: 'Binary body (hex view): parameters not parsed.' }
  const te = headerValues(m.headers, 'transfer-encoding').join(',').toLowerCase()
  if (te.includes('chunked')) return { rows: [], note: 'Chunked body: stored with its chunk framing, parameters not parsed.' }
  const ce = headerValues(m.headers, 'content-encoding').join(',').trim()
  if (ce !== '' && ce.toLowerCase() !== 'identity') return { rows: [], note: `Encoded body (${ce}): parameters not parsed.` }
  const partial = m.bodyViewTruncated ? 'Body is truncated in view: parameters from the first part only.' : undefined

  if (type === 'application/x-www-form-urlencoded') return { rows: parseFormEncoded(m.body), note: partial }
  if (type === 'application/json' || type.endsWith('+json')) {
    const rows = parseJsonTopLevel(m.body)
    if (rows) return { rows, note: partial }
    return {
      rows: [],
      note: m.bodyViewTruncated ? 'Body is truncated in view, so the JSON is cut off: keys not parsed.' : 'Not valid JSON (or a bare value): no top-level keys.',
    }
  }
  if (type === 'multipart/form-data') {
    const boundary = contentTypeParam(ct, 'boundary')
    if (boundary === '') return { rows: [], note: 'multipart/form-data without a boundary: fields not parsed.' }
    return { rows: parseMultipart(m.body, boundary), note: partial }
  }
  if (type === '' || type === 'text/plain') return sniffBody(m.body, type, partial)
  return { rows: [], note: `Content-Type ${type}: no parameters to parse.` }
}

/**
 * A body sent as text/plain (or with no Content-Type) that is really JSON or
 * form data. Many servers parse the body whatever the Content-Type says,
 * and text/plain makes a cross-site POST a "simple" request with no CORS
 * preflight: the classic way to deliver a JSON CSRF.
 */
function sniffBody(body: string, type: string, partial: string | undefined): BodyResult {
  const label = type === '' ? 'No Content-Type' : `Content-Type ${type}`
  const why = 'A server that ignores Content-Type will read it, and this type needs no CORS preflight (CSRF).'
  const trimmed = body.trim()
  const json = trimmed.startsWith('{') || trimmed.startsWith('[') ? parseJsonTopLevel(body) : null
  if (json) return { rows: json, note: [`${label}, but the body is JSON. ${why}`, partial].filter(Boolean).join(' ') }
  if (FORM_SHAPE.test(trimmed))
    return { rows: parseFormEncoded(trimmed), note: [`${label}, but the body is form data. ${why}`, partial].filter(Boolean).join(' ') }
  return { rows: [], note: `${label}: no parameters to parse.` }
}

const NOT_CAPTURED = 'Not captured.'

const SPACE_IN_NAME: Flag = {
  tone: 'warn',
  label: 'space before colon',
  why: 'Whitespace between the header name and the colon. RFC 9112 §5.1 says servers must reject it; a lenient one may accept it, and that disagreement is how request smuggling starts.',
}

function headerRows(m: MessageInput, policy: DupePolicy): Row[] {
  return withDupes(
    m.headers.map((h) =>
      h.malformed
        ? plain('(malformed line)', h.value, [{ tone: 'warn', label: 'malformed', why: 'No colon, or an obsolete line fold: strict parsers reject this line.' }])
        : plain(h.name, h.value, h.name !== h.name.trim() ? [SPACE_IN_NAME] : []),
    ),
    policy,
  )
}

/** Brackets an IPv6 literal so a port after it reads unambiguously ("[::1]:8080"). */
const hostForDisplay = (host: string) => (host.includes(':') && !host.startsWith('[') ? `[${host}]` : host)

// Encoded separators and dots are the classic access-control bypass shapes:
// a proxy or filter checks one form of the path, the app routes on another.
// The decoded value hides them, so flag them on the raw path.
const ENCODED_PATH = /%(2f|5c|2e|25|00)/i

function encodedPathFlags(path: string): Flag[] {
  return ENCODED_PATH.test(path)
    ? [{ tone: 'warn', label: 'encoded separator', why: 'The raw path holds %2f, %5c, %2e, %25 or %00. Front ends and apps often decode these differently, which can bypass path-based access checks. Turn on Raw values to see it.' }]
    : []
}

function attributeRows(req: MessageInput, line: RequestLine, target: Target, ctx: ExchangeContext): Draft[] {
  const defaultPort = (ctx.scheme === 'https' && ctx.port === 443) || (ctx.scheme === 'http' && ctx.port === 80)
  const host = hostForDisplay(ctx.host)
  const rows: Draft[] = []
  if (req.captured) rows.push(plain('Method', line.method))
  rows.push(plain('Scheme', ctx.scheme), plain('Host', defaultPort || ctx.port === 0 ? host : `${host}:${ctx.port}`))
  if (!req.captured) return rows
  if (line.method === 'CONNECT') {
    rows.push(plain('Target', line.target))
  } else {
    const spaced = /\s/.test(line.target)
      ? [{ tone: 'warn' as const, label: 'space in target', why: 'The request target contains whitespace, which HTTP forbids. Servers split such a line differently.' }]
      : []
    rows.push({ name: 'Path', rawName: 'Path', value: visible(percentDecode(target.path, false)), raw: target.path, flags: [...spaced, ...encodedPathFlags(target.path)] })
  }
  if (target.fragment !== null)
    rows.push(
      plain('Fragment', target.fragment, [
        { tone: 'warn', label: 'fragment sent', why: 'Clients never send #fragment. Servers differ on whether they strip it or treat it as part of the path or query.' },
      ]),
    )
  if (ctx.tunnel) rows.push(plain('Tunnel', `not decrypted: ${ctx.tunnel}`))
  return rows
}

/** Everything the Inspector shows for one exchange, in display order. */
export function inspect(req: MessageInput, res: MessageInput, ctx: ExchangeContext, now: number): Inspection {
  const line = parseRequestLine(req.startLine)
  const target = splitTarget(line.target, line.method === 'CONNECT')
  const reqNote = req.captured ? undefined : NOT_CAPTURED
  const resNote = res.captured ? undefined : NOT_CAPTURED
  const body = req.captured ? bodyParams(req) : { rows: [], note: NOT_CAPTURED }
  const sections: Section[] = [
    { id: 'attributes', title: 'Request attributes', rows: withDupes(attributeRows(req, line, target, ctx)), note: reqNote },
    { id: 'query', title: 'Request query parameters', rows: target.query === null ? [] : parseFormEncoded(target.query), note: reqNote },
    { id: 'body', title: 'Request body parameters', rows: body.rows, note: body.note },
    { id: 'reqCookies', title: 'Request cookies', rows: parseCookieHeader(headerValues(req.headers, 'cookie')), note: reqNote },
    { id: 'reqHeaders', title: 'Request headers', rows: headerRows(req, REQUEST_HEADER_DUPES), note: reqNote },
    { id: 'resHeaders', title: 'Response headers', rows: headerRows(res, RESPONSE_HEADER_DUPES), note: resNote },
    { id: 'resCookies', title: 'Response cookies', rows: parseSetCookies(headerValues(res.headers, 'set-cookie'), now, ctx.scheme), note: resNote },
  ]
  return { protocol: protocolInfo(req, res, line.version, ctx), sections }
}

// ---------------------------------------------------------------------------
// Search (the detail pane's search field)
// ---------------------------------------------------------------------------

/** A row with its index in its section: the index stays its key while a search hides other rows. */
export type IndexedRow = readonly [number, Row]

/** A section as the search leaves it. */
export type SectionMatch = {
  readonly section: Section
  /** Every row without a search; only the matching ones with one. */
  readonly rows: readonly IndexedRow[]
  /** Whether the Protocol row is shown (only ever in the attributes section). */
  readonly protocol: boolean
}

/**
 * A row matches on its name, value or detail (a cookie's attributes), decoded
 * or as captured: the Raw values toggle only changes which form is shown.
 */
export const rowMatches = (r: Row, m: Matcher): boolean =>
  matches(r.name, m) || matches(r.value, m) || matches(r.rawName, m) || matches(r.raw, m) || (r.detail !== undefined && matches(r.detail, m))

const protocolMatches = (info: ProtocolInfo, m: Matcher) => matches('Protocol', m) || matches(info.used, m) || matches(info.note, m)

/** Every section with the rows the search leaves; all rows when there is no search. */
export function searchInspection(result: Inspection, matcher: Matcher | null): SectionMatch[] {
  const protocol = matcher === null || protocolMatches(result.protocol, matcher)
  return result.sections.map((section) => {
    const all = section.rows.map((r, i): IndexedRow => [i, r])
    return {
      section,
      rows: matcher === null ? all : all.filter(([, r]) => rowMatches(r, matcher)),
      protocol: section.id === 'attributes' && protocol,
    }
  })
}

/** How many rows the search leaves in the Inspector, the Protocol row included. */
export const matchedRows = (sections: readonly SectionMatch[]): number =>
  sections.reduce((n, s) => n + s.rows.length + (s.protocol ? 1 : 0), 0)
