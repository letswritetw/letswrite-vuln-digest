// OWASP Top 10:2025 類別名稱，來源 https://top10.owasp.org/2025/（與 scripts/owasp-2025.js 相同）。
export const OWASP_2025_NAMES: Record<string, string> = {
  'A01:2025': 'Broken Access Control',
  'A02:2025': 'Security Misconfiguration',
  'A03:2025': 'Software Supply Chain Failures',
  'A04:2025': 'Cryptographic Failures',
  'A05:2025': 'Injection',
  'A06:2025': 'Insecure Design',
  'A07:2025': 'Authentication Failures',
  'A08:2025': 'Software or Data Integrity Failures',
  'A09:2025': 'Security Logging and Alerting Failures',
  'A10:2025': 'Mishandling of Exceptional Conditions',
};

export function owaspLabel(code: string): string {
  return OWASP_2025_NAMES[code] ? `${code} ${OWASP_2025_NAMES[code]}` : code;
}

export const NO_OWASP = '不在 OWASP Top 10:2025 對照範圍';
