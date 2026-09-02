# ctxscrub

**Scrub secrets. Strip bloat. Pack a clean prompt.**

Paste a messy `.env`, agent dump, or log into an LLM and you leak keys, burn tokens on minified blobs, and smuggle jailbreak lines into the next context window. `ctxscrub` is a tiny, zero-dependency TypeScript library + CLI that scans locally, redacts, and packs for Claude / GPT / Grok / Cursor.

- **Local.** Scanning never leaves the process. No account, no telemetry.
- **Fast.** Regex patterns, not a model. Milliseconds on tens of KB.
- **Pack-ready.** Markdown, Anthropic XML documents, OpenAI JSON messages, or an `AGENTS.md` snippet.

```bash
# Node 22+
node --experimental-strip-types bin/cli.ts --redact --strip --pack xml dirty.txt
```

```ts
import { scan, scrub, pack } from "ctxscrub";

const result = scan(raw);
const packed = pack(raw, result, {
  redact: true,
  strip: true,
  format: "xml",
  title: "auth-bug",
});
```

## What it catches

| Kind | Examples |
| --- | --- |
| **Secrets** | OpenAI / Anthropic / xAI keys, GitHub PATs, Slack, Stripe, AWS, JWTs, PEM / OpenSSH private keys, connection strings, `API_KEY=` assignments |
| **PII** | Emails, phone numbers, Luhn-valid cards, IPv4 |
| **Bloat** | Data URIs, long base64, minified lines, source maps, lockfile dumps |
| **Injection** | “Ignore previous instructions”, DAN / jailbreak personas, fake `system:` role spoofs |

Token counts are **estimates** (not tiktoken). Good enough for a budget bar; not a billing meter.

## CLI

```text
ctxscrub [options] [file]
  --redact          replace secrets + PII (default on)
  --no-redact
  --strip           drop bloat (default on)
  --pack md|xml|json|agents    output format (default md)
  --json            findings as JSON on stderr
```

Reads **stdin** if no file is given. Packed text goes to **stdout**. A one-line summary goes to **stderr**.

```bash
pbpaste | node --experimental-strip-types bin/cli.ts --pack agents > packed.md
```

## Install

Zero runtime dependencies. Copy `src/` into a repo, or:

```bash
git clone https://github.com/hlsitechio/ctxscrub
cd ctxscrub
node --experimental-strip-types --test src/scan.test.ts
```

## Why this exists

AI coding agents get fed `.env` files, CI logs, and 400 KB of vendor JS “for context.” Then the key shows up in a chat transcript, or the model spends half the window on a source map. ctxscrub is the sieve you run **before** paste.

MIT. Built by [Hubert](https://github.com/hlsitechio).
