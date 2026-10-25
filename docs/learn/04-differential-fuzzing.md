# 04 — Differential fuzzing

## The idea

**Fuzzing** means feeding a program huge numbers of generated inputs and watching for crashes, hangs or wrong results. Humans write a few test cases. A fuzzer writes millions.

Random bytes alone rarely get far. A parser rejects most of them on the first line. **Coverage-guided** fuzzing fixes this. The fuzzer watches which code paths each input reaches. An input that reaches new code is kept and mutated further. Over time the fuzzer "learns" the shape of valid input and digs deeper.

Go has this built in. A fuzz target is a test function:

```go
func FuzzParse(f *testing.F) {
    f.Add([]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n")) // seed input
    f.Fuzz(func(t *testing.T, data []byte) {
        // call the code under test with data; t.Fatal on a bug
    })
}
```

- `go test` runs only the seeds and saved inputs, like a normal test.
- `go test -fuzz=FuzzParse` runs the fuzzer until it finds a failure or you stop it.
- The **corpus** lives in `testdata/fuzz/FuzzParse/`. A failing input is saved there, so it becomes a permanent regression test.

The hard part of fuzzing is the check. A crash is easy to spot. But how do you know a parse result is *wrong*? **Differential testing** answers that. Run the same input through two implementations and compare. If they disagree, at least one is wrong. You never need to know the right answer yourself.

## Why it matters

- Parsers are the classic fuzz target. They take untrusted bytes, have many branches, and their edge cases are hard to imagine by hand.
- **Request smuggling is two parsers disagreeing.** A front-end reads one request; the back-end reads two. Differential fuzzing hunts for exactly that: inputs where two parsers see different boundaries.
- A hand-written parser has no reference built in. A mature library like Go's `net/http` is a free second opinion.
- Not every disagreement is a bug. One side may be **stricter on purpose**. If Sluice rejects ambiguous framing that `net/http` accepts, that is the design. Such cases must be classified as **intended divergences**, or the fuzzer reports them forever.
- The dangerous case is the reverse: both accept, but read different methods, targets, headers or bodies. That is a real bug.
- Fuzzing finds bugs over time. A short run on every change catches regressions cheaply. Long runs find the deep cases.

## What Sluice does

- A fuzz target feeds each input to both `engine.ReadRequest` and `net/http.ReadRequest`, then compares results.
- `net/http` is used only here, as a test oracle. It never runs in the proxy path.
- When both accept, the parsed fields must match. A mismatch fails the test.
- When only Sluice rejects, the error must name a known stricter rule (bare CR/LF, obs-fold, CL plus TE, a TE list not ending in a single `chunked`, a bad chunk size line, and so on). The test then re-checks that exact property in the raw bytes, with its own small scanner: a `ErrChunkEnd` passes only if some chunk's data really is not followed by CRLF. A parser that rejects for the wrong reason still fails.
- When only `net/http` rejects, that fails, except for three documented cases where Sluice is looser on purpose. Each is again re-checked in the raw bytes:
  - **Target form.** `net/http` parses the request-target as a URL here. Sluice only checks it has no control bytes or spaces; the proxy layer validates the form later, where it routes.
  - **Equal Content-Length repeats.** `Content-Length: 5, 5` or `05` next to `5`: every element is digits and all are the same number, so every hop reads the same length.
  - **Codings before chunked.** `Transfer-Encoding: gzip, chunked`: final coding `chunked`, appearing once, the others valid token names. Sluice de-chunks and forwards the inner coding untouched.
- Seed inputs cover normal requests and the smuggling rejection cases from page 02. New failures are saved to the corpus (`internal/engine/testdata/fuzz/FuzzReadRequestDifferential/`) as regression tests.
- CI runs the fuzzer for 30 s on every change. Longer runs are done locally, e.g. `go test -run='^$' -fuzz=FuzzReadRequestDifferential -fuzztime=10m ./internal/engine/`.

## Further reading

- [Go — Fuzzing](https://go.dev/doc/security/fuzz/) — how Go native fuzzing works, the corpus, and flags.
- [Go tutorial — Getting started with fuzzing](https://go.dev/doc/tutorial/fuzz) — write and run a first fuzz target.
- [PortSwigger Web Security Academy — HTTP request smuggling](https://portswigger.net/web-security/request-smuggling) — why parser disagreement is an attack.
- [Wikipedia — Fuzzing](https://en.wikipedia.org/wiki/Fuzzing) — history and kinds of fuzzers.
- [Wikipedia — Differential testing](https://en.wikipedia.org/wiki/Differential_testing) — comparing implementations as an oracle.
