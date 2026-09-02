import type { Finding, Kind } from "./types.ts";

export function applyFindings(
  text: string,
  findings: Finding[],
  kinds: ReadonlySet<Kind>,
): { text: string; applied: number } {
  const selected = findings
    .filter((f) => kinds.has(f.kind))
    .sort(
      (a, b) => a.start - b.start || b.end - a.start - (a.end - a.start),
    );

  const kept: Finding[] = [];
  let cursor = 0;
  for (const f of selected) {
    if (f.start < cursor) continue;
    kept.push(f);
    cursor = f.end;
  }

  let next = text;
  for (let i = kept.length - 1; i >= 0; i--) {
    const f = kept[i]!;
    next = next.slice(0, f.start) + f.replacement + next.slice(f.end);
  }
  return { text: next, applied: kept.length };
}

export function collapseWhitespace(text: string): string {
  return text
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

export function scrub(
  text: string,
  findings: Finding[],
  opts: { redact: boolean; strip: boolean },
): string {
  const kinds = new Set<Kind>();
  if (opts.redact) {
    kinds.add("secret");
    kinds.add("pii");
  }
  if (opts.strip) kinds.add("bloat");
  const { text: next } = applyFindings(text, findings, kinds);
  return collapseWhitespace(next);
}
