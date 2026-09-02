import type { Kind, Severity } from "./types.ts";

export interface PatternDef {
  id: string;
  kind: Kind;
  severity: Severity;
  label: string;
  regex: RegExp;
  replacement: string;
  /** Extra gate — return false to skip a match. */
  test?: (match: string) => boolean;
}

function luhnOk(num: string): boolean {
  const digits = num.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = Number(digits[i]);
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

export const PATTERNS: PatternDef[] = [
  {
    id: "pem",
    kind: "secret",
    severity: "critical",
    label: "Private key block",
    regex:
      /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
    replacement: "[REDACTED:private-key]",
  },
  {
    id: "openai",
    kind: "secret",
    severity: "critical",
    label: "OpenAI API key",
    regex: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b/g,
    replacement: "[REDACTED:openai]",
  },
  {
    id: "anthropic",
    kind: "secret",
    severity: "critical",
    label: "Anthropic API key",
    regex: /\bsk-ant-[A-Za-z0-9_-]{16,}\b/g,
    replacement: "[REDACTED:anthropic]",
  },
  {
    id: "xai",
    kind: "secret",
    severity: "critical",
    label: "xAI API key",
    regex: /\bxai-[A-Za-z0-9_-]{20,}\b/g,
    replacement: "[REDACTED:xai]",
  },
  {
    id: "github-fine",
    kind: "secret",
    severity: "critical",
    label: "GitHub fine-grained PAT",
    regex: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
    replacement: "[REDACTED:github-pat]",
  },
  {
    id: "github-pat",
    kind: "secret",
    severity: "critical",
    label: "GitHub token",
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g,
    replacement: "[REDACTED:github]",
  },
  {
    id: "gitlab",
    kind: "secret",
    severity: "critical",
    label: "GitLab token",
    regex: /\bglpat-[A-Za-z0-9_-]{16,}\b/g,
    replacement: "[REDACTED:gitlab]",
  },
  {
    id: "slack",
    kind: "secret",
    severity: "critical",
    label: "Slack token",
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
    replacement: "[REDACTED:slack]",
  },
  {
    id: "stripe",
    kind: "secret",
    severity: "critical",
    label: "Stripe key",
    regex: /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
    replacement: "[REDACTED:stripe]",
  },
  {
    id: "aws-key",
    kind: "secret",
    severity: "critical",
    label: "AWS access key",
    regex: /\b(?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16}\b/g,
    replacement: "[REDACTED:aws-key]",
  },
  {
    id: "google-api",
    kind: "secret",
    severity: "high",
    label: "Google API key",
    regex: /\bAIza[0-9A-Za-z_-]{30,}\b/g,
    replacement: "[REDACTED:google]",
  },
  {
    id: "huggingface",
    kind: "secret",
    severity: "critical",
    label: "Hugging Face token",
    regex: /\bhf_[A-Za-z0-9]{20,}\b/g,
    replacement: "[REDACTED:huggingface]",
  },
  {
    id: "npm",
    kind: "secret",
    severity: "critical",
    label: "npm token",
    regex: /\bnpm_[A-Za-z0-9]{20,}\b/g,
    replacement: "[REDACTED:npm]",
  },
  {
    id: "jwt",
    kind: "secret",
    severity: "high",
    label: "JWT",
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    replacement: "[REDACTED:jwt]",
  },
  {
    id: "bearer",
    kind: "secret",
    severity: "high",
    label: "Bearer token",
    regex: /\bBearer\s+[A-Za-z0-9._\-+=/]{16,}/gi,
    replacement: "Bearer [REDACTED]",
  },
  {
    id: "connection",
    kind: "secret",
    severity: "critical",
    label: "Connection string",
    regex:
      /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|rediss):\/\/[^\s"'`]+/gi,
    replacement: "[REDACTED:connection-string]",
  },
  {
    id: "env-secret",
    kind: "secret",
    severity: "high",
    label: "Env secret assignment",
    regex:
      /(?:^|[\s;])((?:API[_-]?KEY|SECRET[_-]?KEY|ACCESS[_-]?TOKEN|AUTH[_-]?TOKEN|PRIVATE[_-]?KEY|PASSWORD|PASSWD|DB_PASSWORD|AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|XAI_API_KEY|GITHUB_TOKEN|HF_TOKEN)\s*[=:]\s*["']?[^\s"'`]+)(?:["'])?/gim,
    replacement: "[REDACTED:env]",
  },
  {
    id: "email",
    kind: "pii",
    severity: "medium",
    label: "Email address",
    regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    replacement: "[REDACTED:email]",
    test: (m) => !m.toLowerCase().endsWith(".png") && !m.toLowerCase().endsWith(".jpg"),
  },
  {
    id: "phone",
    kind: "pii",
    severity: "medium",
    label: "Phone number",
    regex: /\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b/g,
    replacement: "[REDACTED:phone]",
    test: (m) => m.replace(/\D/g, "").length >= 10,
  },
  {
    id: "card",
    kind: "pii",
    severity: "critical",
    label: "Credit card number",
    regex: /\b(?:\d[ -]*?){13,19}\b/g,
    replacement: "[REDACTED:card]",
    test: luhnOk,
  },
  {
    id: "ipv4",
    kind: "pii",
    severity: "low",
    label: "IPv4 address",
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b/g,
    replacement: "[REDACTED:ip]",
    test: (m) => !m.startsWith("127.") && m !== "0.0.0.0" && !m.startsWith("255."),
  },
  {
    id: "data-uri",
    kind: "bloat",
    severity: "medium",
    label: "Embedded data URI",
    regex: /data:(?:image|application|audio|video)\/[a-z0-9+.-]+;base64,[A-Za-z0-9+/=\s]{80,}/gi,
    replacement: "[STRIPPED:data-uri]",
  },
  {
    id: "base64-blob",
    kind: "bloat",
    severity: "medium",
    label: "Long base64 blob",
    regex: /(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{400,}={0,2}(?![A-Za-z0-9+/])/g,
    replacement: "[STRIPPED:base64]",
  },
  {
    id: "minified",
    kind: "bloat",
    severity: "low",
    label: "Minified line",
    regex: /^(?=.*[{};])(?=.{500,}).+$/gm,
    replacement: "[STRIPPED:minified-line]",
  },
  {
    id: "sourcemap",
    kind: "bloat",
    severity: "low",
    label: "Source map comment",
    regex: /\/\/[#@]\s*sourceMappingURL=.+$/gm,
    replacement: "[STRIPPED:sourcemap]",
  },
  {
    id: "lockfile",
    kind: "bloat",
    severity: "low",
    label: "Lockfile dump",
    regex:
      /(?:^|\n)(?:package-lock-json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock)\b[\s\S]{200,}/gi,
    replacement: "[STRIPPED:lockfile]",
  },
  {
    id: "inject-ignore",
    kind: "inject",
    severity: "high",
    label: "Ignore-instructions jailbreak",
    regex:
      /\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts|rules|context)\b/gi,
    replacement: "[FLAGGED:prompt-injection]",
  },
  {
    id: "inject-dan",
    kind: "inject",
    severity: "high",
    label: "Jailbreak persona",
    regex:
      /\b(?:you are now (?:DAN|do anything now|jailbroken|unrestricted|no longer bound)|developer mode enabled|jailbreak(?:ed)? mode)\b/gi,
    replacement: "[FLAGGED:jailbreak]",
  },
  {
    id: "inject-system",
    kind: "inject",
    severity: "medium",
    label: "Fake system role",
    regex: /(?:^|\n)\s*(?:system|assistant)\s*:\s*(?:you are|ignore|new instructions)/gim,
    replacement: "[FLAGGED:role-spoof]",
  },
];
