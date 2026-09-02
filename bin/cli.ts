#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { pack, scan, type PackFormat } from "../src/index.ts";

function usage(): never {
  console.error(`ctxscrub [options] [file]
  --redact / --no-redact   replace secrets + PII (default on)
  --strip / --no-strip     drop bloat (default on)
  --pack md|xml|json|agents
  --json                   findings JSON on stderr
  Reads stdin when no file is given.`);
  process.exit(2);
}

const args = process.argv.slice(2);
let redact = true;
let strip = true;
let format: PackFormat = "markdown";
let json = false;
let file: string | undefined;

for (let i = 0; i < args.length; i++) {
  const a = args[i]!;
  if (a === "--help" || a === "-h") usage();
  else if (a === "--redact") redact = true;
  else if (a === "--no-redact") redact = false;
  else if (a === "--strip") strip = true;
  else if (a === "--no-strip") strip = false;
  else if (a === "--json") json = true;
  else if (a === "--pack") {
    const v = args[++i];
    const map: Record<string, PackFormat> = {
      md: "markdown",
      markdown: "markdown",
      xml: "xml",
      json: "json",
      agents: "agents",
    };
    if (!v || !map[v]) usage();
    format = map[v]!;
  } else if (a.startsWith("-")) usage();
  else file = a;
}

const source = file
  ? readFileSync(file, "utf8")
  : readFileSync(0, "utf8");

const result = scan(source);
const packed = pack(source, result, {
  redact,
  strip,
  format,
  title: file ?? "stdin",
});

if (json) {
  console.error(
    JSON.stringify(
      {
        tokensIn: result.tokens,
        tokensOut: packed.tokens,
        counts: result.counts,
        findings: result.findings.map((f) => ({
          kind: f.kind,
          label: f.label,
          severity: f.severity,
          preview: f.preview,
        })),
      },
      null,
      2,
    ),
  );
} else {
  console.error(
    `ctxscrub  secrets=${result.counts.secret} pii=${result.counts.pii} bloat=${result.counts.bloat} inject=${result.counts.inject}  ~${packed.tokens} tok packed`,
  );
}

process.stdout.write(packed.output);
if (!packed.output.endsWith("\n")) process.stdout.write("\n");
