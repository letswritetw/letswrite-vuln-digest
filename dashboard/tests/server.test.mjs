import { test } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createDashboardServer } from '../server.mjs';

const sample = (date = '2026-10-16') => ({
  schemaVersion: 1, date, generatedAt: `${date}T01:00:00Z`, timeZone: 'Asia/Taipei', model: 'gemini-3.5-flash-lite',
  coverage: { fromUtc: '2026-10-14T19:00:00Z', toUtc: `${date}T01:00:00Z`, sources: ['NVD', 'CISA'], note: '測試' },
  stats: { totalNvdInWindow: 0, totalRecords: 0, kevAddedInWindow: 0, analyzedCount: 0, unanalyzedCount: 0, selectedButNotAnalyzed: 0, possiblyRelevantAnalyzed: 0 },
  executiveSummaryZh: '目前無符合條件的情報。', records: [],
});

async function setup(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'cwe-dashboard-'));
  const reportsDir = path.join(root, 'reports'); const distDir = path.join(root, 'dist');
  await fs.mkdir(reportsDir); await fs.mkdir(distDir);
  await fs.writeFile(path.join(distDir, 'index.html'), '<h1>資安戰情室</h1>');
  const server = createDashboardServer({ reportsDir, distDir });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => {
    server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
    assert(path.resolve(root).startsWith(path.resolve(os.tmpdir()) + path.sep));
    await fs.rm(root, { recursive: true, force: true });
  });
  const get = (url, options = {}) => fetch(`${base}${url}`, options);
  const write = async (report, monthly = true) => {
    const directory = monthly ? path.join(reportsDir, report.date.slice(0, 4), report.date.slice(5, 7)) : reportsDir;
    await fs.mkdir(directory, { recursive: true });
    await fs.writeFile(path.join(directory, `security-daily-${report.date}.json`), JSON.stringify(report));
    await fs.writeFile(path.join(directory, `security-daily-${report.date}.md`), `# 日報 ${report.date}\n<script>alert('xss')</script>`);
  };
  return { reportsDir, distDir, get, write };
}

test('內網免登入可讀網站與 API，仍拒絕寫入方法', async t => {
  const { get, write, reportsDir } = await setup(t);
  const report = sample(); await write(report);
  await fs.writeFile(path.join(reportsDir, 'latest.json'), JSON.stringify(report));
  for (const route of ['/', '/api/reports', '/api/reports/latest']) {
    const response = await get(route);
    assert.equal(response.status, 200); assert.equal(response.headers.get('www-authenticate'), null);
  }
  const page = await get('/'); assert.equal(page.status, 200); assert.match(await page.text(), /資安戰情室/);
  for (const method of ['POST', 'PUT', 'DELETE']) assert.equal((await get('/api/reports', { method })).status, 405);
});

test('零筆日報、latest、年月與舊平面歷史、JSON/MD下載皆相容', async t => {
  const { get, write, reportsDir } = await setup(t);
  const current = sample(); const old = sample('2026-09-01');
  await write(current); await write(old, false);
  await fs.writeFile(path.join(reportsDir, 'latest.json'), JSON.stringify(current));
  assert.deepEqual(await (await get('/api/reports')).json(), { reports: [{ date: current.date }, { date: old.date }], latestDate: current.date });
  assert.deepEqual(await (await get('/api/reports/latest')).json(), current);
  assert.deepEqual(await (await get(`/api/reports/${old.date}`)).json(), old);
  const json = await get(`/api/reports/${current.date}?download=1`);
  assert.match(json.headers.get('content-disposition'), /security-daily-2026-10-16.json/);
  const markdown = await get(`/api/reports/${current.date}/markdown?download=1`);
  assert.match(markdown.headers.get('content-type'), /text\/markdown/);
  assert.match(markdown.headers.get('content-disposition'), /\.md/);
  assert.match(await markdown.text(), /日報/);
  assert.match(markdown.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.equal(markdown.headers.get('cache-control'), 'no-store');
});

test('空目錄、缺少 latest 與損毀資料有不同結果，不偽造成功', async t => {
  const { get, reportsDir, write } = await setup(t);
  assert.deepEqual(await (await get('/api/reports')).json(), { reports: [], latestDate: null });
  assert.equal((await get('/api/reports/latest')).status, 404);
  await fs.writeFile(path.join(reportsDir, 'latest.json'), '{');
  assert.equal((await get('/api/reports/latest')).status, 422);
  for (const bad of [ { ...sample(), schemaVersion: 9 }, { ...sample(), stats: { ...sample().stats, totalRecords: 1 } },
    { ...sample(), records: [{ id: 'invalid', cwes: [], analysisStatus: 'not_analyzed' }] } ]) {
    await fs.writeFile(path.join(reportsDir, 'latest.json'), JSON.stringify(bad));
    assert.equal((await get('/api/reports/latest')).status, 422);
  }
  await write({ ...sample(), schemaVersion: 9 });
  assert.deepEqual((await (await get('/api/reports')).json()).reports, []);
  await write(sample());
  assert.equal((await (await get('/api/reports')).json()).reports.length, 1);
  await fs.writeFile(path.join(reportsDir, '2026/10/security-daily-2026-10-16.json'), JSON.stringify(sample('2026-10-15')));
  assert.equal((await get('/api/reports/2026-10-16')).status, 422);
});

test('部分蒐集及舊版可空 CWE／null AI 欄位保留，統計須一致', async t => {
  const { get, reportsDir } = await setup(t);
  const report = sample(); report.coverage.nvd = { status: 'partial', limitPerKeyword: 100, queries: [] };
  report.records = [{ id: 'CVE-2026-12345', cwes: [], analysisStatus: 'not_analyzed', priority: null, summaryZh: null }];
  report.stats.totalNvdInWindow = 1; report.stats.totalRecords = 1; report.stats.unanalyzedCount = 1;
  await fs.writeFile(path.join(reportsDir, 'latest.json'), JSON.stringify(report));
  assert.deepEqual(await (await get('/api/reports/latest')).json(), report);
});

test('日期、路徑與參數白名單，不公開報告目錄或主機路徑', async t => {
  const { get } = await setup(t);
  for (const route of ['/api/reports/2026-02-30', '/api/reports/2026-13-01', '/api/reports/latest?file=secret', '/api/reports/latest?download=no', '/api/%2e%2e%2fserver.mjs', '/%2e%2e%5cserver.mjs', '/server.mjs', '/reports/latest.json']) {
    const response = await get(route); assert([400, 404].includes(response.status), route);
    assert(!(await response.text()).includes('AppData'));
  }
});

test('報告目錄無法讀取時回報故障，非零筆成功', async t => {
  const { get, reportsDir } = await setup(t);
  await fs.rename(reportsDir, `${reportsDir}-hidden`);
  assert.equal((await get('/api/reports')).status, 503);
  // 不把缺少掛載目錄轉成空 reports 回應。
  assert.match((await (await get('/api/reports')).json()).error, /目錄/);
});

test('符號連結無法跳出報告根目錄', async t => {
  const { get, reportsDir } = await setup(t);
  const outside = path.join(path.dirname(reportsDir), 'outside');
  await fs.mkdir(path.join(outside, '10'), { recursive: true });
  await fs.writeFile(path.join(outside, '10/security-daily-2026-10-16.json'), JSON.stringify(sample()));
  await fs.symlink(outside, path.join(reportsDir, '2026'), process.platform === 'win32' ? 'junction' : 'dir');
  assert.equal((await get('/api/reports/2026-10-16')).status, 403);
  assert.deepEqual((await (await get('/api/reports')).json()).reports, []);
});

test('損毀的可選欄位不可進入前端，避免 join/filter 型別錯誤', async t => {
  const { get, reportsDir } = await setup(t);
  for (const change of [report => report.coverage.filter = { keywords: 'windows' },
    report => report.coverage.nvd = { status: 'partial', queries: {} }, report => report.coverage.sources = 1,
    report => { report.records = [{ id: 'CVE-2026-12345', cwes: [], analysisStatus: 'not_analyzed', matchedKeywords: {} }]; }]) {
    const report = sample(); change(report);
    await fs.writeFile(path.join(reportsDir, 'latest.json'), JSON.stringify(report));
    assert.equal((await get('/api/reports/latest')).status, 422);
  }
});

const extended = () => {
  const report = sample();
  report.records = [
    { id: 'CVE-2026-70001', cwes: ['CWE-78'], analysisStatus: 'ai_analyzed', priority: 'P1', sourceType: 'NVD', ghsaId: null,
      advisoryType: null, patchedVersions: [], packages: [], affectedVersions: [], audience: ['全員電腦', '開發者'], routine: false,
      vendorManaged: false, disputed: false, vendorAdvisoryUrls: ['https://git-scm.com/'], owasp: ['A05:2025'], product: 'Git',
      isCompanyProduct: true, fixVersionZh: '2.47.1 以上', fixQuoteEn: 'Fixed in 2.47.1.', fixQuoteZh: '已修正。', kevActionZh: null,
      fixVerified: true, actionType: 'must_do' },
    { id: 'GHSA-2345-6789-cfgh', cwes: [], analysisStatus: 'not_analyzed', sourceType: 'GHSA', ghsaId: 'GHSA-2345-6789-cfgh',
      advisoryType: 'malware', patchedVersions: [], packages: ['axios'], affectedVersions: ['= 1.14.1'], audience: ['開發者'],
      routine: false, vendorManaged: false, disputed: false, vendorAdvisoryUrls: [], owasp: ['A03:2025'], product: 'axios',
      isCompanyProduct: null, fixVersionZh: null, fixQuoteEn: null, fixQuoteZh: null, kevActionZh: null, fixVerified: false, actionType: 'must_do' },
  ];
  Object.assign(report.stats, { totalNvdInWindow: 1, totalRecords: 2, analyzedCount: 1, unanalyzedCount: 1,
    mustDoCount: 2, routineCount: 0, fyiCount: 0, cweGuidesMissing: 0 });
  report.coverage.ghsa = { status: 'complete', packages: ['axios'], reviewedCount: 0, malwareCount: 1 };
  report.coverage.nvd = { status: 'complete', limitPerKeyword: 100, keepPerKeyword: 10,
    queries: [{ keyword: 'git', totalResults: 1, returnedCount: 1, eligibleCount: 1, keptCount: 1, truncated: false }] };
  report.actionPlan = { mustDo: [
    { kind: 'malware', product: 'axios', audience: ['開發者'], fixVersions: [], owasp: ['A03:2025'], recordIds: ['GHSA-2345-6789-cfgh'] },
    { kind: 'update', product: 'Git', audience: ['全員電腦', '開發者'], fixVersions: ['2.47.1 以上'], owasp: ['A05:2025'], recordIds: ['CVE-2026-70001'] },
  ], routineCount: 0, routineByKeyword: {}, fyiCount: 0, unanalyzedCandidates: 0 };
  report.cweGuides = [{ cwe: 'CWE-78', nameZh: '指令注入', riskZh: '可執行任意指令。', handlingZh: '更新並避免組字串執行指令。',
    nameEn: 'OS Command Injection', owasp: ['A05:2025'] }];
  return report;
};

test('新版日報的必做清單、CWE 說明與 GitHub 公告紀錄可讀', async t => {
  const { get, reportsDir } = await setup(t);
  const report = extended();
  await fs.writeFile(path.join(reportsDir, 'latest.json'), JSON.stringify(report));
  const response = await get('/api/reports/latest');
  assert.equal(response.status, 200); assert.deepEqual(await response.json(), report);
});

test('新欄位型別錯誤回 422', async t => {
  const { get, reportsDir } = await setup(t);
  for (const change of [r => { r.records[0].actionType = 'urgent'; }, r => { r.records[0].audience = ['老闆']; },
    r => { r.records[0].owasp = ['A11:2025']; }, r => { r.actionPlan.mustDo[0].recordIds = ['CVE-2026-99999']; },
    r => { r.cweGuides[0].cwe = 'XSS'; }, r => { r.cweGuides.push({ ...r.cweGuides[0] }); },
    r => { r.coverage.ghsa.status = 'unknown'; }, r => { r.stats.mustDoCount = 5; },
    r => { r.records[1].advisoryType = 'other'; }, r => { r.records[0].isCompanyProduct = 'yes'; },
    r => { r.actionPlan.mustDo[0].kind = 'urgent'; }, r => { r.coverage.nvd.queries[0].keptCount = -1; },
    r => { r.records[0].patchedVersions = 'x'; }, r => { r.records[1].id = 'GHSA-bad'; },
    r => { r.actionPlan.unanalyzedCandidates = -1; }]) {
    const report = extended(); change(report);
    await fs.writeFile(path.join(reportsDir, 'latest.json'), JSON.stringify(report));
    assert.equal((await get('/api/reports/latest')).status, 422, change.toString());
  }
});

test('沒有新欄位的舊版日報仍可讀', async t => {
  const { get, reportsDir } = await setup(t);
  await fs.writeFile(path.join(reportsDir, 'latest.json'), JSON.stringify(sample()));
  assert.equal((await get('/api/reports/latest')).status, 200);
});
