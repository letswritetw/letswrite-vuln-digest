// 只允許 http(s) 外部連結；其他協定（例如 javascript:）一律不產生連結。
export function safeUrl(value: unknown): string | undefined {
  if (typeof value !== 'string') return;
  try {
    const url = new URL(value);
    if (url.protocol === 'http:' || url.protocol === 'https:') return url.href;
  } catch { /* Invalid source URLs remain plain text. */ }
}

export function cweUrl(cwe: string): string | undefined {
  const match = /^CWE-(\d+)$/.exec(cwe);
  return match ? `https://cwe.mitre.org/data/definitions/${match[1]}.html` : undefined;
}
