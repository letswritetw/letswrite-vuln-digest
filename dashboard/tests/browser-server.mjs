// 僅供本機瀏覽器測試的假資料，不讀取或覆寫正式 reports。
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createDashboardServer } from '../server.mjs';

const reportsDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cwe-browser-'));
const generatedAt = new Date().toISOString();
const date = new Intl.DateTimeFormat('sv-SE', { timeZone: 'Asia/Taipei' }).format(new Date());
const base = { sourceType: 'NVD', ghsaId: null, advisoryType: null, patchedVersions: [], packages: [], affectedVersions: [],
  routine: false, vendorManaged: false, disputed: false, vendorAdvisoryUrls: [], isKev: false, fixVerified: false,
  isCompanyProduct: null, fixVersionZh: null, fixQuoteEn: null, fixQuoteZh: null, kevActionZh: null };
const gitFix = { fixVersionZh: '2.47.1 以上', fixQuoteEn: 'Fixed in 2.47.1.', fixQuoteZh: '已於 2.47.1 版修正。', fixVerified: true,
  isCompanyProduct: true, product: 'Git', audience: ['全員電腦', '開發者'], owasp: ['A05:2025'], matchedKeywords: ['git'],
  analysisStatus: 'ai_analyzed', relevance: '可能相關', reasonZh: '測試環境列有 Git。', actionZh: '更新到修補版本。', actionType: 'must_do' };
const records = [
  { ...base, id: 'GHSA-2345-6789-cfgh', sourceType: 'GHSA', ghsaId: 'GHSA-2345-6789-cfgh', advisoryType: 'malware', cwes: ['CWE-506'],
    packages: ['axios'], affectedVersions: ['= 1.14.1'], audience: ['開發者'], owasp: ['A03:2025', 'A08:2025'], product: 'axios',
    analysisStatus: 'not_analyzed', priority: null, descriptionEn: 'Malicious code in axios.', actionType: 'must_do',
    sourceUrl: 'https://github.com/advisories/GHSA-2345-6789-cfgh' },
  { ...base, ...gitFix, id: 'CVE-2026-10001', cwes: ['CWE-78'], priority: 'P1', cvss: 8.1, summaryZh: 'Git 指令注入弱點待確認',
    descriptionEn: 'Git before 2.47.1 allows command injection. Fixed in 2.47.1.', sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-10001' },
  { ...base, ...gitFix, id: 'CVE-2026-10004', cwes: ['CWE-78'], priority: 'P2', cvss: 6.5, summaryZh: 'Git 參數處理弱點待確認',
    descriptionEn: 'Git option parsing flaw. Fixed in 2.47.1.', sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-10004' },
  { ...base, id: 'CVE-2026-10006', cwes: ['CWE-269'], matchedKeywords: ['windows'], routine: true, isKev: true, kevDateAdded: '2026-10-15',
    kevRequiredAction: 'Apply mitigations per vendor instructions.', kevActionZh: '依廠商指示套用緩解措施。',
    vendorAdvisoryUrls: ['https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-10006'], audience: ['全員電腦', '伺服器管理者'], owasp: [],
    analysisStatus: 'ai_analyzed', priority: 'P0', product: 'Windows', isCompanyProduct: true, summaryZh: 'Windows 核心權限提升，已知被利用',
    relevance: '可能相關', reasonZh: '列入 KEV。', actionZh: '依 CISA 要求處理。', actionType: 'must_do',
    sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-10006', kevUrl: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' },
  { ...base, id: 'CVE-2026-10005', cwes: ['CWE-269'], matchedKeywords: ['windows'], routine: true, audience: ['全員電腦', '伺服器管理者'],
    owasp: [], analysisStatus: 'not_analyzed', priority: null, product: null, descriptionEn: 'Windows Kernel flaw.', actionType: 'routine',
    sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-10005' },
  { ...base, id: 'CVE-2026-10003', cwes: ['CWE-200'], matchedKeywords: ['docker'], audience: ['伺服器管理者'], owasp: ['A01:2025'],
    analysisStatus: 'not_analyzed', priority: null, product: null, descriptionEn: 'Docker information disclosure.', actionType: 'fyi',
    sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2026-10003' },
  { ...base, id: 'CVE-2026-10002', cwes: ['CWE-89'], matchedKeywords: ['node.js'], audience: ['開發者'], owasp: ['A05:2025'],
    analysisStatus: 'ai_analyzed', priority: 'P2', product: 'Node.js', isCompanyProduct: false, summaryZh: 'Node.js 查詢處理弱點待確認',
    relevance: '較低相關', reasonZh: '第三方函式庫。', actionZh: '確認是否使用。', actionType: 'fyi', sourceUrl: 'javascript:alert(1)' },
];
const report = {
  schemaVersion: 1, date, generatedAt, timeZone: 'Asia/Taipei', model: 'gemini-3.5-flash-lite',
  coverage: { fromUtc: new Date(Date.now() - 30 * 3600000).toISOString(), toUtc: generatedAt,
    sources: ['NVD', 'CISA', 'GitHub Advisory Database'], filter: { keywords: ['git', 'windows', 'docker', 'node.js'], dateField: 'published', requiresCwe: true },
    nvd: { status: 'partial', limitPerKeyword: 100, keepPerKeyword: 10,
      queries: [{ keyword: 'windows', totalResults: 101, returnedCount: 100, eligibleCount: 40, keptCount: 10, truncated: true }] },
    ghsa: { status: 'complete', packages: ['axios'], reviewedCount: 0, malwareCount: 1 },
    note: '本次資料範圍說明，不代表使用環境已受影響。' },
  stats: { totalNvdInWindow: 100, totalRecords: 7, analyzedCount: 4, unanalyzedCount: 3, selectedButNotAnalyzed: 0, possiblyRelevantAnalyzed: 3,
    kevAddedInWindow: 1, mustDoCount: 4, routineCount: 1, fyiCount: 2, cweGuidesMissing: 1 },
  executiveSummaryZh: '本日有兩項必做：axios 惡意版本與 Git 更新，實際受影響版本仍待確認。',
  actionPlan: { mustDo: [
    { kind: 'malware', product: 'axios', audience: ['開發者'], fixVersions: [], owasp: ['A03:2025', 'A08:2025'], recordIds: ['GHSA-2345-6789-cfgh'] },
    { kind: 'kev', product: 'Windows', audience: ['全員電腦', '伺服器管理者'], fixVersions: [], owasp: [], recordIds: ['CVE-2026-10006'] },
    { kind: 'update', product: 'Git', audience: ['全員電腦', '開發者'], fixVersions: ['2.47.1 以上'], owasp: ['A05:2025'], recordIds: ['CVE-2026-10001', 'CVE-2026-10004'] },
  ], routineCount: 1, routineByKeyword: { windows: 1 }, fyiCount: 2, unanalyzedCandidates: 0 },
  cweGuides: [{ cwe: 'CWE-78', nameZh: '作業系統指令注入', riskZh: '攻擊者可讓程式執行任意系統指令。',
    handlingZh: '更新到修補版；自家程式勿把使用者輸入直接組成指令。', nameEn: 'OS Command Injection', owasp: ['A05:2025'] }],
  records,
};
const quiet = { ...report, date: '2026-01-01', generatedAt: '2026-01-01T01:00:00Z',
  stats: { ...report.stats, totalRecords: 1, analyzedCount: 0, unanalyzedCount: 1, possiblyRelevantAnalyzed: 0, mustDoCount: 0, routineCount: 0, fyiCount: 1, cweGuidesMissing: 0 },
  executiveSummaryZh: '本日沒有必做項目。', actionPlan: { mustDo: [], routineCount: 0, routineByKeyword: {}, fyiCount: 1, unanalyzedCandidates: 1 }, cweGuides: [],
  records: [records.find(r => r.id === 'CVE-2026-10003')] };
const old = { ...report, date: '2020-01-01', generatedAt: '2020-01-01T01:00:00Z',
  coverage: { fromUtc: '2019-12-31T01:00:00Z', toUtc: '2020-01-01T01:00:00Z', sources: ['NVD'] },
  stats: { totalNvdInWindow: 0, totalRecords: 0, analyzedCount: 0, unanalyzedCount: 0, selectedButNotAnalyzed: 0, possiblyRelevantAnalyzed: 0, kevAddedInWindow: 0 },
  executiveSummaryZh: '這是零筆歷史報告，未呼叫 Gemini。', records: [] };
delete old.actionPlan; delete old.cweGuides;
await fs.writeFile(path.join(reportsDir, 'latest.json'), JSON.stringify(report));
for (const item of [report, quiet, old]) {
  await fs.writeFile(path.join(reportsDir, `security-daily-${item.date}.json`), JSON.stringify(item));
  await fs.writeFile(path.join(reportsDir, `security-daily-${item.date}.md`), '# 測試日報\n\n> 產生時間：2026-10-19T03:25:14Z（UTC）\n> 情報視窗：2026-10-17 ～ 2026-10-19\n\n可閱讀的官方摘要。\n<script>window.__xss=1</script>\n<img src=x onerror="window.__xss=1">\n[危險連結](javascript:alert(1))\n[官方來源](https://nvd.nist.gov/)');
}
const server = createDashboardServer({ reportsDir });
server.listen(3031, '127.0.0.1');
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => {
  server.closeAllConnections();
  server.close(async () => { await fs.rm(reportsDir, { recursive: true, force: true }); process.exit(); });
});
