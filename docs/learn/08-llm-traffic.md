# 08 — Spotting LLM traffic: what it looks like, and why a proxy flags it

## The idea

Almost every app that "has AI in it" talks to a model over plain HTTP with JSON. The shapes are few and very regular, because most providers copy each other:

**OpenAI Chat Completions** (also spoken by many "OpenAI-compatible" servers: vLLM, LM Studio, llama.cpp, Ollama's compatibility layer):

```http
POST /v1/chat/completions HTTP/1.1
Content-Type: application/json
Authorization: Bearer sk-...

{"model":"gpt-4o-mini","messages":[{"role":"system","content":"You are..."},{"role":"user","content":"hi"}],"stream":true}
```

OpenAI's newer **Responses API** is `POST /v1/responses` with `model` and `input`; embeddings are `POST /v1/embeddings` with `model` and `input`.

**Anthropic Messages**:

```http
POST /v1/messages HTTP/1.1
x-api-key: ...
anthropic-version: 2023-06-01
Content-Type: application/json

{"model":"claude-...","max_tokens":1024,"system":"You are...","messages":[{"role":"user","content":"hi"}]}
```

**Ollama** (local models, default port 11434): `POST /api/chat` with `model` + `messages`, or `POST /api/generate` with `model` + `prompt`.

The pattern: a `model` name, plus either a `messages` array of `{role, content}` turns (the conversation) or a single `prompt` string. `content` can be a string or an array of parts (text, images, tool results).

### Token streaming with Server-Sent Events

Models produce text one token at a time, and users want to see it appear. So the APIs stream: with `"stream": true` the response is `Content-Type: text/event-stream` (Server-Sent Events, SSE). The body is a long-lived stream of small text events:

```text
data: {"choices":[{"delta":{"content":"Hel"}}]}

data: {"choices":[{"delta":{"content":"lo"}}]}

data: [DONE]
```

Each event is `field: value` lines ended by a blank line. Anthropic adds `event:` names (`message_start`, `content_block_delta`, `message_stop`). On HTTP/1.1 the response is usually chunked, and it stays open until the model finishes. The full answer only exists after you join every delta, which is why reassembly is its own job (Deep detection, M6). Ollama is the odd one out: it streams newline-delimited JSON (`application/x-ndjson`), not SSE.

## Why it matters

To a security tester, an LLM endpoint is a new kind of input sink with its own failure modes, collected in the [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/):

- **Prompt injection (LLM01).** The model cannot reliably tell instructions from data. Anything that reaches the `messages`, whether typed by a user or pulled from a web page, email or document, can steer it. You first have to know *which* request carries the prompt before you can tamper with it.
- **Sensitive information disclosure (LLM02).** Apps paste secrets, customer records and internal documents into prompts. Seeing the outbound `messages` shows exactly what data leaves for a third-party model.
- **System prompt leakage (LLM07).** The `system` text often holds business rules, or even credentials. It is right there in the request.
- **Cost and abuse.** Every call costs money; unbounded loops are a denial-of-wallet.

A proxy is the natural place to find these endpoints: the browser or app already sends you every request, so you can map the AI surface of an app without reading its code ([06](06-why-a-proxy.md)).

### Passive vs active detection

- **Passive**: look at traffic that already happened and label it. Free, invisible to the target, and safe, because it sends nothing. It only finds what the app actually used.
- **Active**: send probes (for example, POST a chat-shaped body to `/v1/chat/completions` on every host, or ask "what model are you?") and watch the reply. It finds hidden endpoints, but it generates traffic, can cost money, and must respect scope.

Sluice's M2 flag is purely passive. Active probing belongs with the attack module (M6), where the engine enforces scope.

## What Sluice does

Every finished exchange runs through `internal/detect` before it goes to the live grid and the store, so both carry the same `is_llm` flag and an `llm_reason` (which rules hit, e.g. `path,json,sse`). Any one rule is enough:

| Rule | Matches | False positives | False negatives |
|------|---------|-----------------|-----------------|
| `path` | The path (query ignored, optional trailing `/`) is one of `/v1/chat/completions`, `/v1/responses`, `/v1/messages`, `/v1/embeddings`, `/api/chat`, `/api/generate`. Case-sensitive. | Any app that happens to use `/api/chat` for a human chat feature, or `/v1/messages` for a mail API. | Providers with other routes (Gemini's `/v1beta/models/...:generateContent`, Azure's `/openai/deployments/...`), and apps that wrap the model behind their own route (`/api/assistant`). |
| `json` | The request body is JSON (Content-Type `application/json` or `+json`, or the body starts with `{`) with a non-empty `model` string and either a `prompt` or a non-empty `messages[]` whose every item has `role` and `content`. | A non-LLM API that just happens to use that shape (a support-ticket API with `model` + `messages`). | Compressed bodies (`Content-Encoding`), bodies over 1 MiB, other field names (`input`, `query`, `contents`), and app-level chat endpoints that send only `{"message": "..."}`, which are M6's lower-confidence heuristic. |
| `sse` | Response `Content-Type` is `text/event-stream`, any case, parameters ignored. | Every non-LLM SSE stream: live scores, notifications, build logs. Treat `sse` alone as "worth a look", not proof. | Non-streamed answers, and Ollama's NDJSON streaming. |

How the JSON rule stays safe on hostile input:

- It re-parses the captured head with the engine's own strict parser, so it sees the same framing the proxy forwarded, and decodes chunked framing with the engine's `ChunkedReader` before parsing.
- It reads at most 1 MiB of decoded body. Anything bigger, or a stored copy that was truncated, is simply not flagged by body.
- It uses `encoding/json`, which reports bad input as an error, never a panic. Wrong types (`"model": 3`) are a non-match. A fuzz test (`FuzzLLM`) feeds it random heads and bodies.
- Detection only labels rows. It never modifies, blocks or replays traffic, and it logs nothing.

In the History grid, flagged rows show a purple **LLM** badge; hover for the matched rules. The "LLM only" toggle shows only flagged rows, and the query `llm:sse` (or `llm:path`, `llm:json`, `llm:any`, `-llm:any`) filters by rule.

## Further reading

- [OpenAI API reference — Chat](https://developers.openai.com/api/reference/resources/chat) — the `model` + `messages` shape most servers copy.
- [OpenAI — Streaming responses](https://developers.openai.com/api/docs/guides/streaming-responses) — SSE token deltas.
- [OpenAI OpenAPI spec](https://github.com/openai/openai-openapi) — every endpoint path, machine-readable.
- [Anthropic — Messages API](https://docs.anthropic.com/en/api/messages) — `/v1/messages`, `system`, content blocks.
- [Anthropic — Streaming](https://docs.anthropic.com/en/docs/build-with-claude/streaming) — named SSE events.
- [Ollama API](https://github.com/ollama/ollama/blob/main/docs/api.md) — `/api/chat`, `/api/generate`, NDJSON streaming.
- [WHATWG HTML — Server-sent events](https://html.spec.whatwg.org/multipage/server-sent-events.html) — the `text/event-stream` format.
- [MDN — Using server-sent events](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events/Using_server-sent_events) — a gentler introduction.
- [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/) — the risk list Sluice's AI module maps to.
- [OWASP LLM01 — Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [OWASP LLM02 — Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/)
- [OWASP LLM07 — System Prompt Leakage](https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/)
- [Simon Willison — Prompt injection attacks against GPT-3](https://simonwillison.net/2022/Sep/12/prompt-injection/) — where the term was coined.
- [RFC 8259 — JSON](https://www.rfc-editor.org/rfc/rfc8259.html) — what "valid JSON" means for the body rule.
