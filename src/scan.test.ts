import assert from "node:assert/strict";
import { test } from "node:test";
import { pack } from "./pack.ts";
import { applyFindings, scrub } from "./redact.ts";
import { scan } from "./scan.ts";
import { SAMPLE_PROMPT } from "./sample.ts";

test("sample dump flags secrets, pii, bloat, and injection", () => {
  const result = scan(SAMPLE_PROMPT);
  assert.ok(result.counts.secret >= 6, "expected multiple secrets");
  assert.ok(result.counts.pii >= 2, "expected email/phone/ip");
  assert.ok(result.counts.bloat >= 1, "expected bloat");
  assert.ok(result.counts.inject >= 1, "expected jailbreak phrase");
  assert.ok(result.tokens > 100);
});

test("redaction removes openai-shaped keys", () => {
  const src = "key=sk-proj-" + "abcdefghijklmnopqrstuvwxyz0123456789ABCD" + " done";
  const result = scan(src);
  const next = scrub(src, result.findings, { redact: true, strip: false });
  assert.equal(next.includes("sk-proj-"), false);
  assert.ok(next.includes("[REDACTED:openai]"));
});

test("overlapping pem + base64 keeps a single replacement", () => {
  const src =
    "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQAAACAexampleexampleexampleexampleexampleexampleexamAAA\n" +
    "-----END OPENSSH PRIVATE KEY-----";
  const result = scan(src);
  const { applied, text } = applyFindings(
    src,
    result.findings,
    new Set(["secret", "bloat"]),
  );
  assert.ok(applied >= 1);
  assert.ok(text.includes("[REDACTED:private-key]"));
  assert.equal((text.match(/REDACTED:private-key/g) || []).length, 1);
});

test("pack xml escapes brackets", () => {
  const src = "hello <script>alert(1)</script>";
  const result = scan(src);
  const packed = pack(src, result, {
    redact: true,
    strip: true,
    format: "xml",
  });
  assert.ok(packed.output.includes("&" + "lt;script" + "&" + "gt;"));
  assert.equal(packed.output.includes("<script>"), false);
});
