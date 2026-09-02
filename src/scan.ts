import { PATTERNS } from "./patterns.ts";
import { estimateTokens } from "./tokens.ts";
import type { Finding, Kind, ScanResult, Severity } from "./types.ts";

export function maskSecret(value: string): string {
  const compact = value.replace(/\s+/g, " ").trim();
  if (compact.length <= 8) return "••••";
  const head = compact.slice(0, 4);
  const tail = compact.slice(-3);
  return `${head}…${tail}`;
}

function overlaps(aStart: number, aEnd: number, bStart: number, bEnd: number) {
  return aStart < bEnd && bStart < aEnd;
}

export function scan(text: string): ScanResult {
  const findings: Finding[] = [];
  let seq = 0;

  for (const pattern of PATTERNS) {
    const re = new RegExp(pattern.regex.source, pattern.regex.flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const raw = m[0];
      if (!raw) continue;
      const match = m[1] ?? raw;
      if (pattern.test && !pattern.test(match)) continue;
      const start = m.index + (m[1] ? raw.indexOf(m[1]) : 0);
      const end = start + match.length;
      // Prefer earlier / more severe matches; skip nested duplicates of same kind.
      const clash = findings.find(
        (f) => overlaps(f.start, f.end, start, end) && f.kind === pattern.kind,
      );
      if (clash) {
        if (end - start > clash.end - clash.start) {
          findings.splice(findings.indexOf(clash), 1);
        } else {
          continue;
        }
      }
      findings.push({
        id: `${pattern.id}-${seq++}`,
        kind: pattern.kind,
        severity: pattern.severity,
        label: pattern.label,
        start,
        end,
        match,
        preview: maskSecret(match),
        replacement:
          pattern.kind === "bloat"
            ? `${pattern.replacement || "[STRIPPED]"} (${match.length} chars)`
            : pattern.replacement,
      });
      if (m[0].length === 0) re.lastIndex++;
    }
  }

  findings.sort((a, b) => a.start - b.start);

  const secrets = findings.filter((f) => f.kind === "secret");
  const pruned = findings.filter((f) => {
    if (f.kind === "secret") return true;
    return !secrets.some((s) => s.start <= f.start && f.end <= s.end);
  });

  const empty: Record<Kind, number> = {
    secret: 0,
    pii: 0,
    bloat: 0,
    inject: 0,
  };
  const bySeverity: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  for (const f of pruned) {
    empty[f.kind]++;
    bySeverity[f.severity]++;
  }

  const bytes = new TextEncoder().encode(text).length;

  return {
    findings: pruned,
    chars: text.length,
    tokens: estimateTokens(text),
    lines: text ? text.split("\n").length : 0,
    bytes,
    counts: empty,
    bySeverity,
  };
}
