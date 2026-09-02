export type Severity = "critical" | "high" | "medium" | "low";
export type Kind = "secret" | "pii" | "bloat" | "inject";

export interface Finding {
  id: string;
  kind: Kind;
  severity: Severity;
  label: string;
  start: number;
  end: number;
  match: string;
  preview: string;
  replacement: string;
}

export interface ScanResult {
  findings: Finding[];
  chars: number;
  tokens: number;
  lines: number;
  bytes: number;
  counts: Record<Kind, number>;
  bySeverity: Record<Severity, number>;
}

export type PackFormat = "markdown" | "xml" | "json" | "agents";

export interface PackOptions {
  redact: boolean;
  strip: boolean;
  format: PackFormat;
  title?: string;
}

export const MODEL_BUDGETS = [
  { id: "8k", label: "8K", tokens: 8_000 },
  { id: "32k", label: "32K", tokens: 32_000 },
  { id: "128k", label: "128K", tokens: 128_000 },
  { id: "200k", label: "200K", tokens: 200_000 },
  { id: "1m", label: "1M", tokens: 1_000_000 },
] as const;
