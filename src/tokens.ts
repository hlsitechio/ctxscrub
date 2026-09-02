/** Fast client-side token estimate. Not a tokenizer — labeled as estimate in UI. */
export function estimateTokens(text: string): number {
  if (!text) return 0;
  const cjk =
    text.match(
      /[\u4e00-\u9fff\u3400-\u4dbf\u3040-\u30ff\uac00-\ud7af]/g,
    )?.length ?? 0;
  const rest = text.replace(
    /[\u4e00-\u9fff\u3400-\u4dbf\u3040-\u30ff\uac00-\ud7af]/g,
    "",
  );
  // Code / dense punctuation sits closer to 3 chars/token; prose nearer 4.
  const codeWeight = /[{};=<>/\\|]/.test(rest) ? 3.2 : 3.8;
  return Math.max(0, Math.ceil(cjk * 1.6 + rest.length / codeWeight));
}

export function formatTokens(n: number): string {
  if (n < 1_000) return String(n);
  if (n < 10_000) return `${(n / 1_000).toFixed(1)}k`;
  if (n < 1_000_000) return `${Math.round(n / 1_000)}k`;
  return `${(n / 1_000_000).toFixed(2)}M`;
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}
