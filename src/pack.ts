import { estimateTokens } from "./tokens.ts";
import type { PackFormat, PackOptions, ScanResult } from "./types.ts";
import { scrub } from "./redact.ts";

function fence(body: string, lang = "text") {
  const ticks = body.includes("```") ? "````" : "```";
  return `${ticks}${lang}\n${body}\n${ticks}`;
}

export function pack(
  source: string,
  scan: ScanResult,
  options: PackOptions,
): { output: string; tokens: number; chars: number } {
  const body = scrub(source, scan.findings, {
    redact: options.redact,
    strip: options.strip,
  });
  const title = options.title?.trim() || "context";
  const meta = [
    `source_chars: ${source.length}`,
    `packed_chars: ${body.length}`,
    `est_tokens: ${estimateTokens(body)}`,
    `secrets: ${scan.counts.secret}`,
    `pii: ${scan.counts.pii}`,
    `bloat: ${scan.counts.bloat}`,
    `injection_flags: ${scan.counts.inject}`,
    `redacted: ${options.redact}`,
    `stripped: ${options.strip}`,
  ].join("\n");

  let output: string;
  switch (options.format) {
    case "xml":
      output = `<documents>\n  <document index="1">\n    <source>${escapeXml(title)}</source>\n    <meta>\n${escapeXml(meta)}\n    </meta>\n    <document_content>\n${escapeXml(body)}\n    </document_content>\n  </document>\n</documents>`;
      break;
    case "json":
      output = JSON.stringify(
        {
          title,
          meta: {
            sourceChars: source.length,
            packedChars: body.length,
            estTokens: estimateTokens(body),
            counts: scan.counts,
            redacted: options.redact,
            stripped: options.strip,
          },
          messages: [{ role: "user", content: body }],
        },
        null,
        2,
      );
      break;
    case "agents":
      output = [
        `# ${title}`,
        "",
        "> Packed by ctxscrub. Paste into AGENTS.md, CLAUDE.md, or a Cursor rule.",
        "",
        "## Context",
        "",
        body,
        "",
        "## Pack notes",
        "",
        fence(meta, "yaml"),
      ].join("\n");
      break;
    default:
      output = [
        `<!-- ctxscrub pack · ${title} -->`,
        "",
        fence(meta, "yaml"),
        "",
        "## Content",
        "",
        body,
      ].join("\n");
  }

  return {
    output,
    tokens: estimateTokens(output),
    chars: output.length,
  };
}

function escapeXml(s: string): string {
  return s
    .replace(/&/g, "&" + "amp;")
    .replace(/</g, "&" + "lt;")
    .replace(/>/g, "&" + "gt;");
}

export const FORMAT_META: Record<
  PackFormat,
  { label: string; hint: string }
> = {
  markdown: {
    label: "Markdown",
    hint: "Generic paste for ChatGPT, Grok, Gemini",
  },
  xml: {
    label: "XML",
    hint: "Claude / Anthropic document blocks",
  },
  json: {
    label: "JSON",
    hint: "OpenAI-style messages array",
  },
  agents: {
    label: "AGENTS.md",
    hint: "Cursor, Claude Code, Codex rules",
  },
};
