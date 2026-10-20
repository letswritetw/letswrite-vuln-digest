// 全部使用假資料；node:test 是 Node 內建功能。
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { test } = require('node:test');
const base = path.resolve(__dirname, '..');
const { scriptSource } = require('../build.js');
const workflow = JSON.parse(fs.readFileSync(path.join(base, 'workflow/security-intel-gemini.json'), 'utf8'));
const nvdName = '取得 NVD 30h CVE';
const win = { dateTW: '2026-10-16', startUtc: '2026-10-14T17:00:00.000Z', endUtc: '2026-10-15T23:00:00.000Z', companyKeywords: ['sql server'],
  npmPackages: ['axios', 'lodash'] };
function run(file, store = {}, input, DateClass = Date, runIndex = 0) {
  const $ = name => ({ first: () => ({ json: Array.isArray(store[name]) ? store[name][0] : store[name] }),
    all: () => (Array.isArray(store[name]) ? store[name] : [store[name]]).map(json => ({ json })) });
  return new Function('$', '$input', 'Date', '$runIndex', scriptSource(file))
    ($, { first: () => ({ json: input }), all: () => (Array.isArray(input) ? input : [input]).map(json => ({ json })) }, DateClass, runIndex)[0].json;
}
function cve(id) {
  return { cve: { id, published: '2026-10-15T12:00:00.000', descriptions: [{ lang: 'en', value: 'Microsoft SQL Server.' }],
    metrics: { cvssMetricV31: [{ cvssData: { baseScore: 8.1, version: '3.1' } }] },
    weaknesses: [{ description: [{ value: 'CWE-269' }] }] } };
}
const defaultProfile = { audience: ['伺服器管理者'], routine: false, vendorManaged: false, aliases: [] };
function setKeywords(store, keywords, overrides = {}) {
  const target = store['建立時間區間'];
  for (const w of Array.isArray(target) ? target : [target]) {
    w.companyKeywords = keywords;
    w.keywordProfiles = Object.fromEntries(keywords.map(k => [k, { ...defaultProfile, ...overrides[k] }]));
  }
  return store;
}
function fixture() {
  const store = { '建立時間區間': { ...win },
    [nvdName]: [{ totalResults: 2, startIndex: 0, resultsPerPage: 100,
      vulnerabilities: [cve('CVE-2026-12345'), cve('CVE-2026-54321')] }],
    '取得 CISA KEV': { count: 2, vulnerabilities: [
      { cveID: 'CVE-2026-12345', dateAdded: '2026-10-14', product: 'SQL Server', requiredAction: 'Check vendor advisory.' },
      { cveID: 'CVE-2025-98765', dateAdded: '2026-10-15', product: 'SQL Server', requiredAction: 'Check vendor advisory.' }] },
    '取得 GitHub 套件公告': { data: '[]' }, '取得 GitHub 惡意套件': { data: '[]' } };
  Object.defineProperty(store, '彙整關注查詢', { get: () => ({ queries: store.queryGroups ?? [{ keyword: 'sql server', pages: store[nvdName] }] }) });
  return setKeywords(store, ['sql server']);
}
function prepare(store = fixture()) {
  store['整理漏洞與 Gemini 輸入'] = run('02-normalize.js', store); return store;
}
function response(store, edit = () => {}) {
  const data = { executiveSummaryZh: '今天有需要確認的安全情報。',
    analyses: store['整理漏洞與 Gemini 輸入'].selectedIds.map(id => ({ id,
      summaryZh: '官方資料顯示有漏洞公告。', relevance: '無法判定', priority: 'P2',
      reasonZh: '待確認受影響版本。', actionZh: '請比對實際版本與官方公告。',
      product: 'SQL Server', isCompanyProduct: true, fixVersionZh: null, fixQuoteEn: null, fixQuoteZh: null, kevActionZh: null })),
    cweGuides: store['整理漏洞與 Gemini 輸入'].cweGuideTargets.map(cwe => ({ cwe, nameZh: '測試弱點', riskZh: '測試風險', handlingZh: '測試處理' })) };
  edit(data); return { candidates: [{ finishReason: 'STOP', content: { parts: [{ text: JSON.stringify(data) }] } }] };
}
function entry(id, description, extra = {}) {
  const row = cve(id); row.cve.descriptions[0].value = description; Object.assign(row.cve, extra); return row;
}
function page(rows, total = rows.length) { return [{ totalResults: total, startIndex: 0, resultsPerPage: 100, vulnerabilities: rows }]; }
function groups(store, byKeyword) {
  store.queryGroups = Object.entries(byKeyword).map(([keyword, rows]) => ({ keyword, pages: page(rows) })); return store;
}
test('OWASP 2025 對照表來自官方清單且可查詢', () => {
  const t = new Function(fs.readFileSync(path.join(base, 'scripts/owasp-2025.js'), 'utf8') +
    '; return { OWASP_2025_CATEGORIES, OWASP_2025_CWES, owaspCategoriesFor };')();
  assert.equal(Object.keys(t.OWASP_2025_CATEGORIES).length, 10);
  assert.equal(t.OWASP_2025_CATEGORIES['A03:2025'], 'Software Supply Chain Failures');
  assert.deepEqual(t.OWASP_2025_CWES['CWE-1395'].categories, ['A03:2025']);
  assert.deepEqual(t.owaspCategoriesFor(['CWE-1395', 'CWE-99999', 'CWE-1395']), ['A03:2025']);
  for (const [cwe, info] of Object.entries(t.OWASP_2025_CWES)) {
    assert.match(cwe, /^CWE-\d+$/); assert(info.nameEn.trim());
    for (const c of info.categories) assert(c in t.OWASP_2025_CATEGORIES, cwe);
  }
  assert(Object.keys(t.OWASP_2025_CWES).length > 100);
});
test('精確查詢 30 小時，台灣跨年日期正確', () => {
  class FixedDate extends Date { constructor(value) { super(value ?? '2026-12-31T23:00:00Z'); } }
  const actual = run('01-window.js', {}, undefined, FixedDate);
  assert.equal(Date.parse(actual.endUtc) - Date.parse(actual.startUtc), 30 * 3600000);
  assert.equal(actual.dateTW, '2027-01-01');
});
test('正常報告維持 schema、統計、CVE 集合與年/月路徑', () => {
  const store = prepare(); const out = run('03-report.js', store, response(store));
  const report = JSON.parse(out.jsonText);
  assert.equal(report.schemaVersion, 1); assert.equal(report.date, win.dateTW);
  assert.equal(report.model, require('../config.json').model);
  assert.equal(workflow.nodes.find(n => n.name === 'Gemini 資安分析').parameters.url,
    `https://generativelanguage.googleapis.com/v1beta/models/${report.model}:generateContent`);
  assert.equal(out.reportSubdir, '2026/10'); assert.equal(report.stats.analyzedCount, 2);
  assert.equal(report.stats.selectedButNotAnalyzed, 0); assert(out.markdown.includes('30 小時'));
  assert.equal(report.coverage.nvd.status, 'complete');
  assert.deepEqual(report.records.map(r => r.id), store['整理漏洞與 Gemini 輸入'].records.map(r => r.id));
});
test('超過 35 筆仍保留所有情報，未選取資料維持未分析', () => {
  const store = setKeywords(fixture(), ['sql server', 'docker', 'nginx', 'gitea']);
  groups(store, Object.fromEntries(['sql server', 'docker', 'nginx', 'gitea'].map((keyword, k) =>
    [keyword, Array.from({ length: 10 }, (_, i) => entry(`CVE-2026-${10000 + k * 10 + i}`, `A ${keyword} vulnerability.`))])));
  prepare(store); const report = JSON.parse(run('03-report.js', store, response(store)).jsonText);
  assert.equal(report.stats.analyzedCount, 35); assert.equal(report.stats.unanalyzedCount, 5);
  assert.equal(report.records.filter(r => r.analysisStatus === 'not_analyzed' && r.summaryZh === null).length, 5);
  assert(report.records.filter(r => r.analysisStatus === 'not_analyzed').every(r => r.actionType === 'fyi'));
  assert.equal(report.actionPlan.unanalyzedCandidates, 5);
  assert(run('03-report.js', store, response(store)).markdown.includes('另有 5 筆可能必做的情報因 AI 分析上限未判定，列於知悉即可。'));
});
test('正常空來源可產生零筆報告', () => {
  const store = fixture(); store[nvdName] = [{ totalResults: 0, startIndex: 0, resultsPerPage: 0, vulnerabilities: [] }];
  store['取得 CISA KEV'] = { count: 0, vulnerabilities: [] }; prepare(store);
  const report = JSON.parse(run('03-report.js', store, response(store)).jsonText);
  assert.equal(report.stats.totalRecords, 0); assert.equal(report.stats.analyzedCount, 0);
  assert.equal(report.coverage.nvd.status, 'complete');
});
test('只接受第一頁；不足預期筆數、多頁、非零起點或重複 CVE 均失敗', () => {
  const store = fixture();
  const first = { totalResults: 3, startIndex: 0, resultsPerPage: 2, vulnerabilities: [cve('CVE-2026-10000'), cve('CVE-2026-10001')] };
  const last = { totalResults: 3, startIndex: 2, resultsPerPage: 2, vulnerabilities: [cve('CVE-2026-10002')] };
  for (const pages of [[first], [last], [first, last], [first, first], [first, { ...last, totalResults: 4 }],
    [{ ...first, totalResults: 2, vulnerabilities: [cve('CVE-2026-10000'), cve('CVE-2026-10000')] }]]) {
    store[nvdName] = pages; assert.throws(() => run('02-normalize.js', store), /NVD/);
  }
});
test('每詞取得 100 筆但只保留 10 筆', () => {
  const source = Array.from({ length: 100 }, (_, i) => cve(`CVE-2026-${10000 + i}`));
  const pageSize = Number(workflow.nodes.find(n => n.name === nvdName).parameters.queryParameters.parameters.find(p => p.name === 'resultsPerPage').value);
  const store = fixture();
  store[nvdName] = [{ totalResults: source.length, startIndex: 0, resultsPerPage: pageSize, vulnerabilities: source }];
  const out = run('02-normalize.js', store);
  assert.equal(store[nvdName].length, 1);
  assert.equal(out.rawNvdTotal, 100);
  assert.equal(out.records.length, 10);
  assert.equal(out.nvdCoverage.keepPerKeyword, 10);
  assert.equal(out.nvdCoverage.status, 'partial');
  assert.deepEqual(out.nvdCoverage.queries, [{ keyword: 'sql server', totalResults: 100, returnedCount: 100, eligibleCount: 100, keptCount: 10, truncated: true }]);
  for (const page of store[nvdName]) page.totalResults = 101;
  const limited = run('02-normalize.js', store);
  assert.equal(limited.nvdCoverage.status, 'partial');
  assert.deepEqual(limited.nvdCoverage.queries, [{ keyword: 'sql server', totalResults: 101, returnedCount: 100, eligibleCount: 100, keptCount: 10, truncated: true }]);
});
test('完整單字比對：git 不命中 GitHub/digital，vite 不命中 invite，符號關鍵字可命中', () => {
  const store = setKeywords(fixture(), ['git', 'vite', '.net', 'node.js', '7-zip']);
  groups(store, {
    git: [entry('CVE-2026-20001', 'GitHub Actions runner leaks tokens.'), entry('CVE-2026-20002', 'A digital signature bypass in Git.')],
    vite: [entry('CVE-2026-20003', 'An invite link in Vite dev server.')],
    '.net': [entry('CVE-2026-20004', 'ASP.NET Core and .NET 8 denial of service.')],
    'node.js': [entry('CVE-2026-20005', 'Node.js http module request smuggling.')],
    '7-zip': [entry('CVE-2026-20006', '7-Zip archive extraction overflow.')],
  });
  const out = run('02-normalize.js', store); const by = id => out.records.find(r => r.id === id);
  assert.equal(by('CVE-2026-20001'), undefined);
  assert.deepEqual(by('CVE-2026-20002').matchedKeywords, ['git']);
  assert.deepEqual(by('CVE-2026-20003').matchedKeywords, ['vite']);
  assert(by('CVE-2026-20004').matchedKeywords.includes('.net'));
  assert.deepEqual(by('CVE-2026-20005').matchedKeywords, ['node.js']);
  assert.deepEqual(by('CVE-2026-20006').matchedKeywords, ['7-zip']);
});
test('每詞保留 10 筆：依 KEV、CVSS、Patch 參考、公布時間排序', () => {
  const store = fixture();
  const rows = Array.from({ length: 15 }, (_, i) => {
    const row = cve(`CVE-2026-${30000 + i}`); row.cve.metrics.cvssMetricV31[0].cvssData.baseScore = 7;
    row.cve.published = `2026-10-15T${String(6 + i).padStart(2, '0')}:00:00.000`; return row;
  });
  rows[0].cve.metrics.cvssMetricV31[0].cvssData.baseScore = 5;
  rows[1].cve.metrics.cvssMetricV31[0].cvssData.baseScore = 9.8;
  rows[1].cve.references = [{ url: 'https://example.com/patch', tags: ['Patch'] }];
  rows[2].cve.metrics.cvssMetricV31[0].cvssData.baseScore = 9.8;
  delete rows[3].cve.metrics;
  store['取得 CISA KEV'].vulnerabilities.push({ cveID: 'CVE-2026-30000', dateAdded: '2026-10-15', requiredAction: 'Apply updates.' });
  store['取得 CISA KEV'].count++;
  store[nvdName] = page(rows);
  const out = run('02-normalize.js', store);
  const expected = ['CVE-2026-30000', 'CVE-2026-30001', 'CVE-2026-30002',
    ...[14, 13, 12, 11, 10, 9, 8].map(i => `CVE-2026-${30000 + i}`)];
  assert.deepEqual(out.records.map(r => r.id).sort(), expected.sort());
  assert.deepEqual(out.nvdCoverage.queries[0], { keyword: 'sql server', totalResults: 15, returnedCount: 15, eligibleCount: 15, keptCount: 10, truncated: true });
  assert.equal(out.nvdCoverage.status, 'partial');
});
test('Visual Studio Code 命中 vs code 別名，不算例行更新', () => {
  const store = setKeywords(fixture(), ['visual studio', 'vs code'],
    { 'visual studio': { routine: true, audience: ['開發者'] }, 'vs code': { aliases: ['visual studio code'], audience: ['開發者'] } });
  const text = 'Visual Studio Code extension host allows code execution.';
  groups(store, { 'visual studio': [entry('CVE-2026-21001', text)], 'vs code': [entry('CVE-2026-21001', text)] });
  const [record] = run('02-normalize.js', store).records;
  assert.deepEqual(record.matchedKeywords, ['visual studio', 'vs code']);
  assert.equal(record.routine, false);
});
test('例行、代管、爭議與 cloudflared 例外旗標', () => {
  const store = setKeywords(fixture(), ['windows', 'cloudflare'],
    { windows: { routine: true, audience: ['全員電腦', '伺服器管理者'] }, cloudflare: { vendorManaged: true } });
  groups(store, {
    windows: [entry('CVE-2026-22001', 'Windows Kernel elevation of privilege.'),
      entry('CVE-2026-22004', '** DISPUTED ** Windows shell issue.'),
      entry('CVE-2026-22005', 'Windows SMB issue.', { cveTags: [{ sourceIdentifier: 'nvd', tags: ['disputed'] }] })],
    cloudflare: [entry('CVE-2026-22002', 'Cloudflare dashboard leaks session.'),
      entry('CVE-2026-22003', 'cloudflared tunnel client crash on Cloudflare.')],
  });
  const out = run('02-normalize.js', store); const by = id => out.records.find(r => r.id === id);
  assert.equal(by('CVE-2026-22001').routine, true);
  assert.deepEqual(by('CVE-2026-22001').audience, ['全員電腦', '伺服器管理者']);
  assert.equal(by('CVE-2026-22001').vendorManaged, false); assert.equal(by('CVE-2026-22001').disputed, false);
  assert.equal(by('CVE-2026-22002').vendorManaged, true);
  assert.equal(by('CVE-2026-22003').vendorManaged, false);
  assert.equal(by('CVE-2026-22004').disputed, true); assert.equal(by('CVE-2026-22005').disputed, true);
  assert.equal(by('CVE-2026-22001').sourceType, 'NVD'); assert.deepEqual(by('CVE-2026-22001').patchedVersions, []);
});
test('OWASP 類別、cweInfo 與廠商連結', () => {
  const store = fixture(); const row = cve('CVE-2026-23001');
  row.cve.weaknesses = [{ description: [{ value: 'CWE-1395' }, { value: 'CWE-99999' }] }];
  row.cve.references = [{ url: 'https://vendor.example/adv', tags: ['Vendor Advisory'] },
    { url: 'https://git.example/commit', tags: ['Patch'] }, { url: 'https://blog.example/post', tags: [] },
    { url: 'javascript:alert(1)', tags: ['Patch'] }, { url: 'https://vendor.example/adv2', tags: ['Vendor Advisory', 'Patch'] },
    { url: 'https://vendor.example/adv3', tags: ['Patch'] }];
  store[nvdName] = page([row]);
  const out = run('02-normalize.js', store); const [record] = out.records;
  assert.deepEqual(record.owasp, ['A03:2025']);
  assert.deepEqual(out.cweInfo['CWE-1395'], { nameEn: 'Dependency on Vulnerable Third-Party Component', owasp: ['A03:2025'] });
  assert.deepEqual(out.cweInfo['CWE-99999'], { nameEn: null, owasp: [] });
  assert.deepEqual(record.vendorAdvisoryUrls, ['https://vendor.example/adv', 'https://git.example/commit', 'https://vendor.example/adv2']);
});
function advisory(overrides = {}) {
  return { ghsa_id: 'GHSA-2345-6789-cfgh', cve_id: 'CVE-2026-30000', type: 'reviewed',
    html_url: 'https://github.com/advisories/GHSA-2345-6789-cfgh', summary: 'axios SSRF',
    description: 'axios before 1.8.2 allows SSRF.', published_at: '2026-10-15T10:00:00Z', updated_at: '2026-10-15T11:00:00Z',
    withdrawn_at: null, cvss_severities: { cvss_v3: { vector_string: 'CVSS:3.1/AV:N', score: 7.5 }, cvss_v4: { score: 0 } },
    cwes: [{ cwe_id: 'CWE-918', name: 'SSRF' }],
    vulnerabilities: [{ package: { ecosystem: 'npm', name: 'axios' }, vulnerable_version_range: '< 1.8.2', first_patched_version: '1.8.2' }],
    ...overrides };
}
function ghsa(store, reviewed = [], malware = []) {
  store['取得 GitHub 套件公告'] = { data: JSON.stringify(reviewed) };
  store['取得 GitHub 惡意套件'] = { data: JSON.stringify(malware) }; return store;
}
const malwareAdvisory = advisory({ ghsa_id: 'GHSA-9999-aaaa-bbbb', cve_id: null, type: 'malware', cwes: [],
  html_url: 'https://github.com/advisories/GHSA-9999-aaaa-bbbb', cvss_severities: {},
  vulnerabilities: [{ package: { ecosystem: 'npm', name: 'axios' }, vulnerable_version_range: '= 1.14.1', first_patched_version: null }] });
test('GitHub Advisory 正常、零筆與惡意版本', () => {
  const empty = run('02-normalize.js', fixture());
  assert.deepEqual(empty.ghsaCoverage, { status: 'complete', packages: ['axios', 'lodash'], reviewedCount: 0, malwareCount: 0 });
  const out = run('02-normalize.js', ghsa(fixture(), [advisory()], [malwareAdvisory]));
  const reviewed = out.records.find(r => r.id === 'CVE-2026-30000');
  assert.equal(reviewed.sourceType, 'GHSA'); assert.equal(reviewed.ghsaId, 'GHSA-2345-6789-cfgh');
  assert.deepEqual(reviewed.patchedVersions, ['1.8.2']); assert.deepEqual(reviewed.packages, ['axios']);
  assert.equal(reviewed.cvss, 7.5); assert.deepEqual(reviewed.cwes, ['CWE-918']); assert.deepEqual(reviewed.audience, ['開發者']);
  const malware = out.records.find(r => r.id === 'GHSA-9999-aaaa-bbbb');
  assert.equal(malware.advisoryType, 'malware'); assert.deepEqual(malware.cwes, []);
  assert(malware.owasp.includes('A03:2025')); assert.deepEqual(malware.affectedVersions, ['= 1.14.1']);
  assert.deepEqual(malware.patchedVersions, []);
  assert.equal(out.ghsaCoverage.reviewedCount, 1); assert.equal(out.ghsaCoverage.malwareCount, 1);
});
test('帶 CVE 的公告併入 NVD 同筆，不重複', () => {
  const before = run('02-normalize.js', fixture()).records.length;
  const out = run('02-normalize.js', ghsa(fixture(), [advisory({ cve_id: 'CVE-2026-12345' })]));
  assert.equal(out.records.length, before);
  const merged = out.records.find(r => r.id === 'CVE-2026-12345');
  assert.equal(merged.sourceType, 'NVD'); assert.equal(merged.ghsaId, 'GHSA-2345-6789-cfgh');
  assert.equal(merged.advisoryType, 'reviewed'); assert.deepEqual(merged.patchedVersions, ['1.8.2']);
});
test('排除撤回、視窗外與清單外套件；多套件公告只算清單內', () => {
  const pkg = (name, fix) => ({ package: { ecosystem: 'npm', name }, vulnerable_version_range: '< 9', first_patched_version: fix });
  const out = run('02-normalize.js', ghsa(fixture(), [
    advisory({ ghsa_id: 'GHSA-0001-aaaa-bbbb', cve_id: null, withdrawn_at: '2026-10-15T12:00:00Z' }),
    advisory({ ghsa_id: 'GHSA-0002-aaaa-bbbb', cve_id: null, published_at: '2026-10-14T16:00:00Z' }),
    advisory({ ghsa_id: 'GHSA-0003-aaaa-bbbb', cve_id: null, vulnerabilities: [pkg('left-pad', '2.0.0')] }),
    advisory({ ghsa_id: 'GHSA-0004-aaaa-bbbb', cve_id: null, vulnerabilities: [pkg('lodash', '4.17.22'), pkg('left-pad', '2.0.0')] }),
    advisory({ ghsa_id: 'GHSA-0005-aaaa-bbbb', cve_id: null, vulnerabilities: [pkg('axios', null), pkg('lodash', '4.17.22')] }),
  ]));
  const ids = out.records.filter(r => r.sourceType === 'GHSA').map(r => r.id).sort();
  assert.deepEqual(ids, ['GHSA-0004-aaaa-bbbb', 'GHSA-0005-aaaa-bbbb']);
  const four = out.records.find(r => r.id === 'GHSA-0004-aaaa-bbbb');
  assert.deepEqual(four.packages, ['lodash']); assert.deepEqual(four.patchedVersions, ['4.17.22']);
  const five = out.records.find(r => r.id === 'GHSA-0005-aaaa-bbbb');
  assert.deepEqual(five.packages, ['axios', 'lodash']); assert.deepEqual(five.patchedVersions, ['lodash@4.17.22']);
});
test('GitHub 回傳 100 筆標為部分蒐集；格式錯誤或來源失敗停止發布', () => {
  const many = Array.from({ length: 100 }, (_, i) => advisory({ ghsa_id: `GHSA-${String(i).padStart(4, '0')}-aaaa-bbbb`, cve_id: null }));
  assert.equal(run('02-normalize.js', ghsa(fixture(), many)).ghsaCoverage.status, 'partial');
  for (const data of ['not json', '{"message":"API rate limit exceeded"}', JSON.stringify([{ ...malwareAdvisory }])]) {
    const store = fixture(); store['取得 GitHub 套件公告'] = { data };
    assert.throws(() => run('02-normalize.js', store), /GitHub Advisory/);
  }
  const missing = fixture(); missing['取得 GitHub 惡意套件'] = {};
  assert.throws(() => run('02-normalize.js', missing), /GitHub Advisory/);
});
test('GitHub 查詢節點接在 CISA 之後，以文字取得回應', () => {
  const nodes = new Map(workflow.nodes.map(n => [n.name, n]));
  const after = name => workflow.connections[name].main[0][0].node;
  assert.equal(workflow.nodes.length, 23);
  assert.equal(after('取得 CISA KEV'), '取得 GitHub 套件公告');
  assert.equal(after('取得 GitHub 套件公告'), '取得 GitHub 惡意套件');
  assert.equal(after('取得 GitHub 惡意套件'), '整理漏洞與 Gemini 輸入');
  for (const [name, type] of [['取得 GitHub 套件公告', 'reviewed'], ['取得 GitHub 惡意套件', 'malware']]) {
    const node = nodes.get(name); const query = node.parameters.queryParameters.parameters;
    assert.equal(node.executeOnce, true); assert.equal(node.parameters.url, 'https://api.github.com/advisories');
    assert.equal(query.find(p => p.name === 'type').value, type);
    assert.equal(query.find(p => p.name === 'ecosystem').value, 'npm');
    assert.equal(query.find(p => p.name === 'affects').value, "={{ $('建立時間區間').first().json.ghsaAffects }}");
    assert.equal(query.find(p => p.name === 'published').value, "={{ $('建立時間區間').first().json.ghsaPublished }}");
    assert.equal(node.parameters.options.response.response.responseFormat, 'text');
    assert.equal(node.parameters.options.response.response.outputPropertyName, 'data');
  }
});
test('AI 選取：KEV 優先，可能必做在例行更新之前，GitHub 公告最後', () => {
  const store = setKeywords(fixture(), ['windows', 'gitea'], { windows: { routine: true } });
  groups(store, {
    windows: Array.from({ length: 5 }, (_, i) => entry(`CVE-2026-4000${i}`, 'Windows component flaw.')),
    gitea: Array.from({ length: 5 }, (_, i) => entry(`CVE-2026-4100${i}`, 'Gitea permission flaw.')),
  });
  store['取得 CISA KEV'].vulnerabilities.push({ cveID: 'CVE-2026-40004', dateAdded: '2026-10-15', requiredAction: 'Apply updates.' });
  store['取得 CISA KEV'].count++;
  const ids = run('02-normalize.js', ghsa(store, [advisory()])).selectedIds; const idx = id => ids.indexOf(id);
  assert.equal(ids[0], 'CVE-2026-40004');
  assert(Math.max(...[0, 1, 2, 3, 4].map(i => idx(`CVE-2026-4100${i}`))) < Math.min(...[0, 1, 2, 3].map(i => idx(`CVE-2026-4000${i}`))));
  assert.equal(ids[ids.length - 1], 'CVE-2026-30000');
});
test('CWE 說明目標包含已選取紀錄與免 AI 必做的 GitHub 公告', () => {
  const keywords = ['sql server', 'docker', 'nginx', 'gitea'];
  const store = groups(setKeywords(fixture(), keywords), Object.fromEntries(keywords.map((keyword, k) =>
    [keyword, Array.from({ length: 10 }, (_, i) => entry(`CVE-2026-${50000 + k * 10 + i}`, `A ${keyword} flaw.`))])));
  const out = run('02-normalize.js', ghsa(store, [], [{ ...malwareAdvisory, cwes: [{ cwe_id: 'CWE-506' }] }]));
  assert.equal(out.selectedIds.length, 35); assert(!out.selectedIds.includes('GHSA-9999-aaaa-bbbb'));
  assert.deepEqual(out.cweGuideTargets, ['CWE-269', 'CWE-506']);
});
test('Gemini 結構描述包含新欄位與 CWE 說明', () => {
  const req = run('02-normalize.js', fixture()).geminiRequest; const schema = req.generationConfig.responseSchema;
  const item = schema.properties.analyses.items;
  for (const key of ['product', 'isCompanyProduct', 'fixVersionZh', 'fixQuoteEn', 'fixQuoteZh', 'kevActionZh']) assert(item.required.includes(key), key);
  assert.equal(item.properties.isCompanyProduct.type, 'BOOLEAN');
  for (const key of ['fixVersionZh', 'fixQuoteEn', 'fixQuoteZh', 'kevActionZh']) assert.equal(item.properties[key].nullable, true, key);
  assert.deepEqual(schema.required, ['executiveSummaryZh', 'analyses', 'cweGuides']);
  assert.deepEqual(schema.properties.cweGuides.items.required, ['cwe', 'nameZh', 'riskZh', 'handlingZh']);
  assert.equal(req.generationConfig.maxOutputTokens, 32000);
  const prompt = req.contents[0].parts[0].text;
  for (const line of ['必做與否由程式依官方欄位判定，你不得宣稱使用環境已受影響。',
    'isCompanyProduct：漏洞發生在關注技術清單所列產品本身時為 true；名稱相近的第三方軟體、外掛，或只是以該平台為執行環境的函式庫為 false。',
    'fixQuoteEn 必須逐字取自該筆 descriptionEn 中提到修補版本的句子；描述沒有寫修補版本時，fixVersionZh、fixQuoteEn、fixQuoteZh 都填 null。',
    'kevActionZh 只在 isKev 為 true 時翻譯 kevRequiredAction，其餘填 null。',
    'cweGuides 必須逐一涵蓋 cweGuideTargets 中的每個 CWE，不得新增其他 CWE；handlingZh 說明更新產品之外，自家程式碼要注意的事。'])
    assert(prompt.includes(line), line);
  assert(prompt.includes('"cweGuideTargets":["CWE-269"]'));
  assert(prompt.includes('關注技術清單：sql server'));
  assert(prompt.includes('每筆的 matchedKeywords 是命中的關注技術清單項目'));
});
const analysisEdit = byId => data => {
  for (const a of data.analyses) Object.assign(a, byId[a.id] || {});
};
test('修補版本核實：摘句須逐字出現、版本號須在摘句內', () => {
  const description = 'Gitea before 1.22.4 allows privilege escalation. This is fixed in\n  version 1.22.4.';
  for (const [quote, version, ok] of [['This is fixed in version 1.22.4.', '1.22.4 以上', true],
    ['This was fixed in version 1.22.4.', '1.22.4 以上', false], ['This is fixed in version 1.22.4.', '1.22.5 以上', false],
    ['This is fixed in version 1.22.4.', '最新版', false], ['This is fixed in version 1.22.4.', '1.22 以上', false],
    ['This is fixed in version 1.22.4.', '22.4 以上', false]]) {
    const store = prepare(groups(setKeywords(fixture(), ['gitea']), { gitea: [entry('CVE-2026-60001', description)] }));
    const ai = response(store, analysisEdit({ 'CVE-2026-60001': { product: 'Gitea', fixQuoteEn: quote, fixVersionZh: version, fixQuoteZh: '已於 1.22.4 版修正。' } }));
    const [record] = JSON.parse(run('03-report.js', store, ai).jsonText).records;
    assert.equal(record.fixVerified, ok, `${quote} ${version}`);
    assert.equal(record.actionType, ok ? 'must_do' : 'fyi', `${quote} ${version}`);
  }
});
test('必做、例行更新與知悉分類規則', () => {
  const store = setKeywords(fixture(), ['windows', 'gitea', 'cloudflare'],
    { windows: { routine: true }, cloudflare: { vendorManaged: true } });
  groups(store, {
    windows: [1, 2, 3, 4].map(i => entry(`CVE-2026-6100${i}`, 'Windows Kernel flaw.')),
    gitea: [entry('CVE-2026-61005', '** DISPUTED ** Gitea before 1.22.4 issue. Fixed in version 1.22.4.')],
    cloudflare: [entry('CVE-2026-61006', 'Cloudflare dashboard issue. Fixed in version 2.0.1.')],
  });
  for (const id of ['CVE-2026-61002', 'CVE-2026-61004']) store['取得 CISA KEV'].vulnerabilities.push({ cveID: id, dateAdded: '2026-10-15', requiredAction: 'Apply updates.' });
  store['取得 CISA KEV'].count += 2;
  ghsa(store, [advisory(), advisory({ ghsa_id: 'GHSA-0007-aaaa-bbbb', cve_id: null,
    vulnerabilities: [{ package: { ecosystem: 'npm', name: 'lodash' }, vulnerable_version_range: '< 9', first_patched_version: null }] })], [malwareAdvisory]);
  prepare(store);
  const ai = response(store, analysisEdit({
    'CVE-2026-61003': { isCompanyProduct: false }, 'CVE-2026-61004': { isCompanyProduct: false },
    'CVE-2026-61005': { fixQuoteEn: 'Fixed in version 1.22.4.', fixVersionZh: '1.22.4 以上', fixQuoteZh: '已修正。' },
    'CVE-2026-61006': { fixQuoteEn: 'Fixed in version 2.0.1.', fixVersionZh: '2.0.1 以上', fixQuoteZh: '已修正。' },
  }));
  const report = JSON.parse(run('03-report.js', store, ai).jsonText);
  const type = id => report.records.find(r => r.id === id).actionType;
  assert.deepEqual(Object.fromEntries(['CVE-2026-61001', 'CVE-2026-61002', 'CVE-2026-61003', 'CVE-2026-61004', 'CVE-2026-61005',
    'CVE-2026-61006', 'CVE-2026-30000', 'GHSA-0007-aaaa-bbbb', 'GHSA-9999-aaaa-bbbb'].map(id => [id, type(id)])), {
    'CVE-2026-61001': 'routine', 'CVE-2026-61002': 'must_do', 'CVE-2026-61003': 'fyi', 'CVE-2026-61004': 'fyi',
    'CVE-2026-61005': 'fyi', 'CVE-2026-61006': 'fyi', 'CVE-2026-30000': 'must_do', 'GHSA-0007-aaaa-bbbb': 'fyi',
    'GHSA-9999-aaaa-bbbb': 'must_do' });
  assert.equal(report.records.find(r => r.id === 'GHSA-9999-aaaa-bbbb').product, 'axios');
  const s = report.stats; assert.equal(s.mustDoCount + s.routineCount + s.fyiCount, s.totalRecords);
  assert.equal(s.mustDoCount, 3); assert.equal(s.routineCount, 1);
});
test('AI 新欄位與 CWE 說明驗證', () => {
  const store = prepare();
  for (const edit of [d => { d.analyses[0].isCompanyProduct = 'yes'; }, d => { d.analyses[0].product = ''; },
    d => { d.analyses[0].fixQuoteEn = 123; }, d => { d.analyses[0].kevActionZh = ' '; },
    d => { d.cweGuides.push({ cwe: 'CWE-1', nameZh: '甲', riskZh: '乙', handlingZh: '丙' }); },
    d => { d.cweGuides.push({ ...d.cweGuides[0] }); }, d => { d.cweGuides[0].riskZh = ''; }, d => { d.cweGuides = {}; }])
    assert.throws(() => run('03-report.js', store, response(store, edit)), /Gemini/);
  const report = JSON.parse(run('03-report.js', store, response(store, d => { d.cweGuides = []; })).jsonText);
  assert.equal(report.stats.cweGuidesMissing, 1); assert.deepEqual(report.cweGuides, []);
});
test('只有免 AI 必做的 GitHub 公告時仍呼叫 Gemini 取得 CWE 說明', () => {
  const store = ghsa(fixture(), [], [{ ...malwareAdvisory, cwes: [{ cwe_id: 'CWE-506' }] }]);
  store[nvdName] = page([]); prepare(store);
  store['整理漏洞與 Gemini 輸入'].selectedIds = [];
  assert.deepEqual(store['整理漏洞與 Gemini 輸入'].cweGuideTargets, ['CWE-506']);
  assert.throws(() => run('03-report.js', store), /Gemini/);
  const report = JSON.parse(run('03-report.js', store, response(store)).jsonText);
  assert.deepEqual(report.cweGuides, [{ cwe: 'CWE-506', nameZh: '測試弱點', riskZh: '測試風險', handlingZh: '測試處理',
    nameEn: 'Embedded Malicious Code', owasp: ['A08:2025'] }]);
  assert.equal(report.records[0].actionType, 'must_do');
});
test('coverage 與 stats 新欄位', () => {
  const store = prepare(); const report = JSON.parse(run('03-report.js', store, response(store)).jsonText);
  assert(report.coverage.sources.includes('GitHub Advisory Database'));
  assert.deepEqual(report.coverage.ghsa, store['整理漏洞與 Gemini 輸入'].ghsaCoverage);
  assert(report.coverage.note.includes('10 筆')); assert(report.coverage.note.includes('間接相依'));
  assert(report.coverage.note.includes('限已取得的首頁'));
  assert(run('03-report.js', store, response(store)).markdown.includes('限已取得的首頁'));
  const s = report.stats; assert.equal(s.mustDoCount + s.routineCount + s.fyiCount, s.totalRecords);
  assert.equal(s.cweGuidesMissing, 0);
});
function cardReport(extra = {}) {
  const store = setKeywords(fixture(), ['git', 'windows', 'gitea'],
    { git: { audience: ['全員電腦', '開發者'] }, windows: { routine: true, audience: ['全員電腦', '伺服器管理者'] } });
  groups(store, {
    git: [entry('CVE-2026-70001', 'Git before 2.47.1 allows code execution. Fixed in 2.47.1.'),
      entry('CVE-2026-70002', 'Git credential helper leak. Fixed in 2.47.1.')],
    windows: [entry('CVE-2026-70003', 'Windows Kernel flaw. Fixed in 1.0.0.',
      { references: [{ url: 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-70003', tags: ['Vendor Advisory'] }] }), entry('CVE-2026-70004', 'Windows Shell flaw.')],
    gitea: [entry('CVE-2026-70005', 'Gitea permission flaw.')],
  });
  store['取得 CISA KEV'].vulnerabilities.push({ cveID: 'CVE-2026-70003', dateAdded: '2026-10-15', requiredAction: 'Apply updates per vendor instructions.' });
  store['取得 CISA KEV'].count++;
  ghsa(store, [advisory({ ghsa_id: 'GHSA-0004-aaaa-bbbb', cve_id: null,
    vulnerabilities: [{ package: { ecosystem: 'npm', name: 'lodash' }, vulnerable_version_range: '< 4.17.22', first_patched_version: '4.17.22' }] })],
  [malwareAdvisory]);
  prepare(store);
  const fix = { fixQuoteEn: 'Fixed in 2.47.1.', fixVersionZh: '2.47.1 以上', fixQuoteZh: '已於 2.47.1 修正。' };
  const ai = response(store, analysisEdit({ 'CVE-2026-70001': { product: 'Git', ...fix }, 'CVE-2026-70002': { product: ' git ', ...fix },
    'CVE-2026-70003': { product: 'Windows', fixQuoteEn: 'Fixed in 1.0.0.', fixVersionZh: '1.0.0 以上', fixQuoteZh: '已修正。', kevActionZh: '依廠商指示套用更新。' },
    'CVE-2026-70004': { product: 'Windows' }, 'CVE-2026-70005': { product: 'Gitea' }, ...extra }));
  const output = run('03-report.js', store, ai);
  return { output, report: JSON.parse(output.jsonText) };
}
test('必做卡片依產品合併並排序', () => {
  const { report } = cardReport(); const plan = report.actionPlan;
  assert.deepEqual(plan.mustDo.map(i => `${i.kind}:${i.product}`), ['malware:axios', 'kev:Windows', 'update:Git', 'update:lodash']);
  const git = plan.mustDo.find(i => i.product === 'Git');
  assert.deepEqual(git.recordIds, ['CVE-2026-70001', 'CVE-2026-70002']);
  assert.deepEqual(git.fixVersions, ['2.47.1 以上']); assert.deepEqual(git.audience, ['全員電腦', '開發者']);
  assert.deepEqual(plan.mustDo.find(i => i.kind === 'kev').recordIds, ['CVE-2026-70003']);
  assert.deepEqual(plan.mustDo.find(i => i.product === 'lodash').fixVersions, ['4.17.22']);
  assert.deepEqual(plan.mustDo[0].fixVersions, []);
  assert.equal(plan.routineCount, 1); assert.deepEqual(plan.routineByKeyword, { windows: 1 }); assert.equal(plan.fyiCount, 1);
  assert.deepEqual(Object.keys(plan.mustDo[0]).sort(), ['audience', 'fixVersions', 'kind', 'owasp', 'product', 'recordIds']);
});
test('Telegram 純文字通知：來源文字不作標記解析、正常與零筆摘要均可輸出', () => {
  const node = workflow.nodes.find(n => n.name === '發送 Telegram 通知');
  assert.equal(workflow.connections['寫入 latest.json'].main[0][0].node, node.name);
  assert.equal(workflow.connections[node.name], undefined);
  assert.equal(node.type, 'n8n-nodes-base.telegram');
  assert(!node.credentials);
  assert.equal(node.parameters.additionalFields.parse_mode, 'HTML');
  assert.equal(node.parameters.additionalFields.appendAttribution, false);
  for (const http of workflow.nodes.filter(n => n.type.endsWith('.httpRequest')))
    assert.equal(Boolean(http.parameters.options.allowUnauthorizedCerts), false, http.name);
  const { output } = cardReport({ 'CVE-2026-70005': { product: 'Gitea' } });
  const text = new Function('$', `return (${node.parameters.text.slice(3, -2)});`)(() => ({ first: () => ({ json: output }) }));
  for (const line of ['資安戰情室｜2026-10-16', '今天要做的事：4 項', '• axios 出現惡意版本', '• 更新 Git（全員電腦、開發者）',
    '例行更新 1 則、知悉即可 1 則', '不代表使用環境已受影響', `儀表板：${require('../config.json').dashboardUrl}`]) assert(text.includes(line), line);
  const injected = cardReport({ 'CVE-2026-70001': { product: '<https://evil.example|點我>', fixQuoteEn: 'Fixed in 2.47.1.', fixVersionZh: '2.47.1 以上', fixQuoteZh: '已修正。' } }).output.chatText;
  assert(!injected.includes('<https://evil.example')); assert(injected.includes('更新 ＜https://evil.example|點我＞'));
  const store = fixture(); store[nvdName][0].vulnerabilities.forEach(r => { r.cve.weaknesses = []; });
  assert(run('03-report.js', prepare(store)).chatText.includes('今天沒有必做項目'));
});

test('Telegram 超長與 emoji 摘要不超過字數限制，仍保留完整儀表板網址', () => {
  const { output } = cardReport({ 'CVE-2026-70001': { product: '產品😀'.repeat(2000) } });
  assert(output.chatText.length <= 4096);
  assert(output.chatText.includes(`儀表板：${require('../config.json').dashboardUrl}`));
  assert(!/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(output.chatText));
});
test('Markdown 依序呈現必做、例行、知悉', () => {
  const md = cardReport().output.markdown;
  for (const line of ['> - 產生時間：', '\n> - 情報視窗：', '\n> - 注意：此報告是外部情報篩選']) assert(md.includes(line), line);
  assert(md.includes('- NVD 每個關鍵字取得首頁最多 100 筆，依重要性保留 10 筆（限已取得的首頁，不代表全體中最重要的 10 筆）。'));
  const heads = ['## 今天要做的事', '## 例行更新涵蓋', '## 今日摘要', '## 情報統計', '## 知悉即可', '## 資料範圍與限制', '## 官方來源'];
  const at = heads.map(h => md.indexOf(h));
  assert(at.every((n, i) => n >= 0 && (i === 0 || n > at[i - 1])), JSON.stringify(at));
  for (const text of ['### axios 出現惡意版本', '### 處理 Windows 已知被利用漏洞', '### 更新 Git', '### 更新 lodash',
    '1. 檢查各專案 lockfile 是否裝到受影響版本（= 1.14.1）', '2. 裝到的機器更換其上的金鑰與密碼', '3. 更新到安全版本',
    '- 更新到：2.47.1 以上', '- 誰要處理：全員電腦、開發者', '- 官方原文：「Fixed in 2.47.1.」（中譯：已於 2.47.1 修正。）',
    '- CISA 要求：Apply updates per vendor instructions.（中譯：依廠商指示套用更新。）', '（AI 說明，未經人工確認）',
    '- 涵蓋：CVE-2026-70001、CVE-2026-70002', '- 列入 KEV：2026-10-15',
    '- 廠商公告：https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-70003',
    '本次例行更新涵蓋 1 則（windows 1），多數由系統例行更新修補，不逐則列出；若為第三方軟體請另行確認，列入 KEV 者已單獨列在上方。', '- CVE-2026-70005｜Gitea｜CWE-269｜'])
    assert(md.includes(text), text);
  assert.equal(md.split('- 官方原文：「Fixed in 2.47.1.」').length, 2);
  const store = fixture(); store['取得 CISA KEV'] = { count: 0, vulnerabilities: [] }; prepare(store);
  const empty = run('03-report.js', store, response(store)).markdown;
  assert(empty.includes('今天沒有必做項目：沒有符合條件的更新，不代表使用環境沒有風險。'));
});
test('同一則 GitHub 公告列出兩個清單內套件時，版本與卡片標明套件名稱', () => {
  const pkg = (name, range, fix) => ({ package: { ecosystem: 'npm', name }, vulnerable_version_range: range, first_patched_version: fix });
  const store = ghsa(fixture(), [advisory({ ghsa_id: 'GHSA-0008-aaaa-bbbb', cve_id: null,
    vulnerabilities: [pkg('axios', '< 1.8.2', '1.8.2'), pkg('lodash', '< 4.17.22', '4.17.22')] })]);
  prepare(store);
  const record = store['整理漏洞與 Gemini 輸入'].records.find(r => r.id === 'GHSA-0008-aaaa-bbbb');
  assert.deepEqual(record.patchedVersions, ['axios@1.8.2', 'lodash@4.17.22']);
  assert.deepEqual(record.affectedVersions, ['axios < 1.8.2', 'lodash < 4.17.22']);
  const plan = JSON.parse(run('03-report.js', store, response(store)).jsonText).actionPlan;
  const card = plan.mustDo.find(i => i.recordIds.includes('GHSA-0008-aaaa-bbbb'));
  assert.equal(card.product, 'axios、lodash'); assert.deepEqual(card.fixVersions, ['axios@1.8.2', 'lodash@4.17.22']);
});
test('Gemini 提示詞要求白話、專有名詞附解釋、不寫程式欄位名稱', () => {
  const prompt = run('02-normalize.js', fixture()).geminiRequest.contents[0].parts[0].text;
  for (const line of [
    '寫作對象是一般使用者，包含不熟資安或該項技術的人；所有中文欄位都用台灣正體中文白話短句，一句只講一件事。',
    '少用專有名詞與英文縮寫；非用不可時，第一次出現就在後面用括號加白話解釋，例如「授權中介軟體（每個請求進來前，先檢查有沒有權限的共用程式）」、「CSRF（跨站請求偽造：騙使用者在不知情時送出操作）」。',
    '不要寫出程式欄位名稱或英文狀態值（例如 nvdCoverage、partial、selectedIds、matchedKeywords、cweGuideTargets），改用白話描述。',
    'reasonZh 用一兩句說明「為什麼要注意」；actionZh 寫成具體可做的動作，例如「把 Gitea 更新到 1.27.3 以上」。',
    'cweGuides 的 nameZh 用一般人看得懂的名稱；riskZh 用一兩句說明「攻擊者可能做到什麼、會造成什麼影響」；handlingZh 先寫要做的事，再補一句原因。',
    '語氣專業、平實，像寫給同事的工作說明；用「攻擊者」「未經授權的人」等一般用語，不用「壞人」這類口語或幼稚的說法。',
    '點名具體產品名稱，不寫「特定軟體」；用詞要完整正確，例如寫「未經身分驗證」，不寫成「未經身分」。',
    '範例：「Xinference 在 Windows 上有路徑穿越漏洞（利用特殊的檔案路徑，存取原本不該碰到的檔案），未經身分驗證的攻擊者可以寫入或刪除任意設定檔。」',
    'fixVersionZh 用中文寫法列出版本，例如「1.27.3 或 28.0.0 以上（依使用的版本系列）」，不要夾雜英文 and、or。',
    'fixQuoteZh 與 kevActionZh 翻成白話中文，產品名稱與版本號保留原文。',
    '整理一段 executiveSummaryZh：只講今天最需要處理的事與整體情況，不用另外說明蒐集範圍或筆數上限；但不能宣稱已涵蓋全部漏洞。',
  ]) assert(prompt.includes(line), line);
  assert(!prompt.includes('可供維運與開發人員執行'));
  assert(!prompt.includes('壞人可能做到什麼'));
  assert(!prompt.includes('部分蒐集'));
});
test('缺少關鍵字屬性時停止發布', () => {
  const store = fixture(); store['建立時間區間'].companyKeywords = ['sql server', 'docker'];
  store.queryGroups = [{ keyword: 'sql server', pages: page([]) }, { keyword: 'docker', pages: page([]) }];
  assert.throws(() => run('02-normalize.js', store), /關注查詢範圍/);
});
test('來源損毀或錯誤回應均不發布', () => {
  for (const bad of [{ error: 'HTTP 503' }, { totalResults: -1, vulnerabilities: [] },
    { totalResults: 0.5, vulnerabilities: [] }, { totalResults: 0, startIndex: 0, resultsPerPage: 0, vulnerabilities: [cve('CVE-2026-12345')] },
    { totalResults: 1, startIndex: 0, resultsPerPage: 1, vulnerabilities: [{ cve: {} }] }]) {
    const store = fixture(); store[nvdName] = [bad]; assert.throws(() => run('02-normalize.js', store), /NVD/);
  }
  for (const bad of [{ error: 'HTTP 503' }, { count: 2, vulnerabilities: [] },
    { count: 1, vulnerabilities: [null] }, { count: 1, vulnerabilities: [{ cveID: 'invalid', dateAdded: '2026-10-15' }] }]) {
    const store = fixture(); store['取得 CISA KEV'] = bad; assert.throws(() => run('02-normalize.js', store), /CISA/);
  }
});
test('KEV 包含起日，但不納入未來日期', () => {
  const store = fixture(); store['取得 CISA KEV'].vulnerabilities.push({ cveID: 'CVE-2026-99999', dateAdded: '2026-10-16' });
  store['取得 CISA KEV'].count++; const out = run('02-normalize.js', store);
  assert(!out.records.some(r => r.id === 'CVE-2026-99999')); assert.equal(out.totalKevAdded, 1);
});
test('AI 額外欄位不能覆寫官方資料及已確認影響狀態', () => {
  const store = prepare(); const ai = response(store, data => Object.assign(data.analyses[0], {
    cvss: 0, cwes: ['CWE-999'], isKev: true, sourceUrl: 'https://example.invalid/', inventoryImpactConfirmed: true, descriptionEn: 'fake' }));
  const report = JSON.parse(run('03-report.js', store, ai).jsonText);
  const original = store['整理漏洞與 Gemini 輸入'].records[0]; const actual = report.records.find(r => r.id === original.id);
  for (const key of ['cvss', 'cwes', 'isKev', 'sourceUrl', 'descriptionEn']) assert.deepEqual(actual[key], original[key]);
  assert.equal(actual.inventoryImpactConfirmed, false);
});
test('AI 缺漏、重複、未知 ID、無效欄位或摘要均拒絕整批', () => {
  const store = prepare();
  for (const edit of [data => data.analyses.pop(), data => data.analyses.push(data.analyses[0]),
    data => data.analyses[0].id = 'CVE-2026-99999', data => data.analyses[0] = null,
    data => data.analyses[0].priority = 'P9', data => data.analyses[0].relevance = '已確認',
    data => data.analyses[0].summaryZh = {}, data => data.analyses[0].actionZh = ' ',
    data => data.executiveSummaryZh = {}, data => data.executiveSummaryZh = '']) {
    assert.throws(() => run('03-report.js', store, response(store, edit)), /Gemini/);
  }
});
test('AI 空回應、非 JSON 或輸出截斷均不發布', () => {
  const store = prepare(); const truncated = response(store); truncated.candidates[0].finishReason = 'MAX_TOKENS';
  for (const bad of [{}, { candidates: [{ finishReason: 'STOP', content: { parts: [{ text: 'not json' }] } }] }, truncated])
    assert.throws(() => run('03-report.js', store, bad), /Gemini/);
});
test('三個轉檔節點使用 n8n 2.42.7 支援的版本與文字輸出欄位', () => {
  // n8n@2.42.7 的 ConvertToFile 只宣告 version: [1, 1.1]。
  const conversions = workflow.nodes.filter(node => node.type === 'n8n-nodes-base.convertToFile');
  assert.equal(conversions.length, 3);
  assert.deepEqual(conversions.map(node => node.parameters.sourceProperty), ['markdown', 'jsonText', 'jsonText']);
  for (const node of conversions) {
    assert.equal(node.typeVersion, 1.1, node.name);
    assert.equal(node.parameters.operation, 'toText');
    assert.equal(node.parameters.binaryPropertyName, 'data');
    assert.equal(node.parameters.options.encoding, 'utf8');
    assert.equal(workflow.connections[node.name].main[0].length, 1);
  }
});
test('工作流關閉分頁、重試、單次 CISA、寫入順序及原始碼同步有效', () => {
  const nodes = new Map(workflow.nodes.map(n => [n.name, n]));
  const visited = new Set(); const queue = ['每天 07:00'];
  while (queue.length) {
    const name = queue.shift(); assert(nodes.has(name));
    if (visited.has(name)) continue;
    visited.add(name);
    for (const edge of workflow.connections[name]?.main?.flat() || []) queue.push(edge.node);
  }
  assert.equal(visited.size, nodes.size);
  const after = name => workflow.connections[name].main[0][0].node;
  assert.equal(after('寫入每日 MD'), '載入報告 JSON');
  assert.equal(after('寫入每日 JSON'), '載入最新 JSON');
  assert.equal(nodes.get(nvdName).parameters.options.pagination, undefined);
  assert.equal(nodes.get(nvdName).parameters.queryParameters.parameters.find(p => p.name === 'startIndex').value, '0');
  assert.equal(nodes.get('取得 CISA KEV').executeOnce, true);
  for (const node of workflow.nodes.filter(n => n.type.endsWith('.httpRequest'))) {
    assert.equal(node.retryOnFail, true); assert.equal(node.maxTries, 3); assert.equal(node.waitBetweenTries, 5000);
    assert(!node.continueOnFail); assert(!node.parameters.options.response?.response?.neverError);
  }
  for (const [name, script] of [['建立時間區間', '01-window.js'], ['收集本次 NVD 分頁', '02-collect.js'], ['整理漏洞與 Gemini 輸入', '02-normalize.js'], ['產生 MD 與 JSON', '03-report.js']])
    assert.equal(nodes.get(name).parameters.jsCode, scriptSource(script));
  assert(nodes.get('整理漏洞與 Gemini 輸入').parameters.jsCode.includes('function owaspCategoriesFor'));
  const store = prepare(); const out = run('03-report.js', store, response(store));
  for (const [name, extension] of [['寫入每日 MD', 'md'], ['寫入每日 JSON', 'json']]) {
    const expr = nodes.get(name).parameters.fileName.slice(3, -2);
    const actual = new Function('$', `return (${expr});`)(() => ({ first: () => ({ json: out }) }));
    assert.equal(actual, `/files/reports/2026/10/security-daily-2026-10-16.${extension}`);
  }
  assert.equal(nodes.get('寫入 latest.json').parameters.fileName, '/files/reports/latest.json');
});
test('時間節點產生關注關鍵字查詢，共用同一個 30 小時區間', () => {
  const config = require('../config.json');
  const items = new Function(scriptSource('01-window.js'))();
  assert.equal(items.length, config.keywords.length);
  assert.deepEqual(items.map(i => i.json.nvdKeyword), config.keywords.map(p => p.keyword));
  assert.equal(new Set(items.map(i => i.json.nvdKeyword)).size, items.length);
  for (const item of items) {
    assert.equal(item.json.startUtc, items[0].json.startUtc);
    assert.equal(item.json.endUtc, items[0].json.endUtc);
    assert.deepEqual(item.json.companyKeywords, items.map(i => i.json.nvdKeyword));
  }
  const w = items[0].json;
  assert.deepEqual(Object.keys(w.keywordProfiles).sort(), [...w.companyKeywords].sort());
  for (const { keyword, ...profile } of config.keywords) assert.deepEqual(w.keywordProfiles[keyword], profile);
  for (const p of Object.values(w.keywordProfiles)) for (const a of p.audience) assert(['全員電腦', '伺服器管理者', '開發者'].includes(a));
  assert.deepEqual(w.npmPackages, config.npmPackages);
  assert.equal(w.ghsaAffects, w.npmPackages.join(','));
  assert.match(w.ghsaPublished, /^\d{4}-\d{2}-\d{2}\.\.\d{4}-\d{2}-\d{2}$/);
  assert.equal(w.ghsaPublished, `${w.startUtc.slice(0, 10)}..${w.endUtc.slice(0, 10)}`);
});
test('NVD 在來源端按單一關注關鍵字查詢，逐詞迴圈且每頁最多 100 筆', () => {
  const nodes = new Map(workflow.nodes.map(n => [n.name, n]));
  const query = nodes.get(nvdName).parameters.queryParameters.parameters;
  assert.equal(query.find(p => p.name === 'keywordSearch').value, '={{ $json.nvdKeyword }}');
  assert.equal(query.find(p => p.name === 'resultsPerPage').value, '100');
  const loop = nodes.get('逐項查詢關注技術');
  assert.equal(loop.type, 'n8n-nodes-base.splitInBatches'); assert.equal(loop.typeVersion, 3);
  assert.equal(loop.parameters.batchSize, 1);
  assert.equal(workflow.connections[loop.name].main[0][0].node, '彙整關注查詢');
  assert.equal(workflow.connections[loop.name].main[1][0].node, nvdName);
  assert.equal(workflow.connections[nvdName].main[0][0].node, '收集本次 NVD 分頁');
  assert.equal(workflow.connections['收集本次 NVD 分頁'].main[0][0].node, '查詢間隔 6 秒');
  assert.equal(workflow.connections['查詢間隔 6 秒'].main[0][0].node, loop.name);
  assert.equal(nodes.get('查詢間隔 6 秒').parameters.amount, 6);
  assert.equal(nodes.get('查詢間隔 6 秒').parameters.unit, 'seconds');
});
test('每詞首頁先驗完整，跨詞同 CVE 去重並保留最新官方內容', () => {
  const store = fixture(); setKeywords(store, ['sql server', 'microsoft']);
  const older = cve('CVE-2026-12345'); older.cve.lastModified = '2026-10-15T01:00:00.000';
  const newer = cve('CVE-2026-12345'); newer.cve.lastModified = '2026-10-15T02:00:00.000';
  newer.cve.metrics.cvssMetricV31[0].cvssData.baseScore = 9.8;
  store.queryGroups = [
    { keyword: 'sql server', pages: [{ totalResults: 1, startIndex: 0, resultsPerPage: 100, vulnerabilities: [older] }] },
    { keyword: 'microsoft', pages: [{ totalResults: 1, startIndex: 0, resultsPerPage: 100, vulnerabilities: [newer] }] },
  ];
  const out = run('02-normalize.js', store);
  assert.equal(out.rawNvdTotal, 1);
  assert.equal(out.records.filter(r => r.sourceType === 'NVD').length, 1);
  assert.equal(out.records.find(r => r.id === newer.cve.id).cvss, 9.8);
});
test('查詢零筆可接受，但缺少整詞、重複詞或未知詞均停止', () => {
  const store = fixture(); setKeywords(store, ['sql server', 'docker']);
  const empty = { keyword: 'docker', pages: [{ totalResults: 0, startIndex: 0, resultsPerPage: 0, vulnerabilities: [] }] };
  const sql = { keyword: 'sql server', pages: store[nvdName] };
  store.queryGroups = [sql, empty]; assert.equal(run('02-normalize.js', store).rawNvdTotal, 2);
  for (const groups of [[sql], [sql, sql], [sql, { ...empty, keyword: 'unknown' }], [sql, { ...empty, pages: [] }]]) {
    store.queryGroups = groups; assert.throws(() => run('02-normalize.js', store), /NVD|關注查詢/);
  }
});
test('關注範圍排除不相關 NVD；KEV 只標記保留的情報，不補入舊漏洞', () => {
  const store = fixture(); store[nvdName][0].vulnerabilities[1].cve.descriptions[0].value = 'An unrelated camera firmware.';
  setKeywords(store, ['SQL SERVER']);
  store.queryGroups = [{ keyword: 'SQL SERVER', pages: store[nvdName] }];
  store['取得 CISA KEV'].vulnerabilities.push({ cveID: 'CVE-2026-99999', dateAdded: '2026-10-15', product: 'Unrelated Camera' });
  store['取得 CISA KEV'].count++;
  const out = run('02-normalize.js', store);
  assert.equal(out.rawNvdTotal, 2); assert.equal(out.records.length, 1); assert.equal(out.totalKevAdded, 1);
  assert(!out.records.some(r => ['CVE-2026-99999', 'CVE-2026-54321'].includes(r.id)));
});
test('回圈逐詞收集首頁，彙整與發布保留篩選範圍', () => {
  const store = fixture(); store['建立時間區間'] = [{ ...win, nvdKeyword: 'sql server' }, { ...win, nvdKeyword: 'docker' }];
  const group = run('02-collect.js', store, [{ totalResults: 0, startIndex: 0, resultsPerPage: 0, vulnerabilities: [] }], Date, 1);
  assert.equal(group.keyword, 'docker'); assert.equal(group.pages.length, 1);
  assert.throws(() => run('02-collect.js', store, [], Date, 99), /關注查詢/);
  const prepared = prepare(); const report = JSON.parse(run('03-report.js', prepared, response(prepared)).jsonText);
  assert.equal(report.schemaVersion, 1);
  assert.deepEqual(report.coverage.filter.keywords, ['sql server']);
  assert(report.coverage.note.includes('關鍵字'));
});
test('多詞關注技術可分開出現，NVD 不要求連續片語；KEV 不補入無 CWE 資料', () => {
  const store = fixture(); setKeywords(store, ['linux kernel']);
  const entry = cve('CVE-2026-10000');
  entry.cve.descriptions[0].value = 'The kernel shipped with Linux allows privilege escalation.';
  entry.cve.configurations = [{ nodes: [{ cpeMatch: [{ vulnerable: true,
    criteria: 'cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*' }] }] }];
  store.queryGroups = [{ keyword: 'linux kernel', pages: [{ totalResults: 1, startIndex: 0,
    resultsPerPage: 100, vulnerabilities: [entry] }] }];
  store['取得 CISA KEV'] = { count: 1, vulnerabilities: [{ cveID: 'CVE-2026-10001',
    dateAdded: '2026-10-15', product: 'Linux', shortDescription: 'A kernel vulnerability.' }] };
  const out = run('02-normalize.js', store);
  assert.equal(out.rawNvdTotal, 1); assert.equal(out.records.length, 1);
  assert(out.records.every(r => r.matchedKeywords.includes('linux kernel')));
});
test('linux kernel 來源 1971 筆取得 100 筆可產報；JSON 保留部分蒐集狀態，MD 與 AI 不另外說明', () => {
  const store = fixture(); setKeywords(store, ['linux kernel']);
  const rows = Array.from({ length: 100 }, (_, index) => {
    const row = cve(`CVE-2026-${10000 + index}`); row.cve.descriptions[0].value = 'A Linux kernel vulnerability.'; return row;
  });
  store.queryGroups = [{ keyword: 'linux kernel', pages: [{ totalResults: 1971, startIndex: 0,
    resultsPerPage: 100, vulnerabilities: rows }] }];
  prepare(store); const prepared = store['整理漏洞與 Gemini 輸入'];
  assert.equal(prepared.rawNvdTotal, 100);
  assert.equal(prepared.nvdCoverage.status, 'partial');
  assert.equal(prepared.nvdCoverage.limitPerKeyword, 100);
  assert(!prepared.geminiRequest.contents[0].parts[0].text.includes('部分蒐集'));
  const output = run('03-report.js', store, response(store)); const report = JSON.parse(output.jsonText);
  assert.equal(report.schemaVersion, 1); assert.equal(report.stats.totalNvdInWindow, 100);
  assert.equal(report.coverage.nvd.status, 'partial');
  assert(!report.coverage.note.includes('部分蒐集'));
  assert(!output.markdown.includes('已取得 100 / 1971 筆'));
  assert(!output.markdown.includes('部分蒐集'));
  assert.deepEqual(report.coverage.nvd.queries[0], { keyword: 'linux kernel', totalResults: 1971, returnedCount: 100, eligibleCount: 100, keptCount: 10, truncated: true });
  assert.equal(report.stats.analyzedCount, 10); assert.equal(report.stats.unanalyzedCount, 0);
  assert.throws(() => run('03-report.js', store, response(store, data => data.analyses.pop())), /Gemini/);
});
test('限量取樣不放行不足 100、超量、異常起點或錯誤頁面大小', () => {
  const rows = Array.from({ length: 100 }, (_, index) => cve(`CVE-2026-${10000 + index}`));
  const valid = { totalResults: 1971, startIndex: 0, resultsPerPage: 100, vulnerabilities: rows };
  for (const bad of [{ ...valid, vulnerabilities: rows.slice(0, 99) }, { ...valid, startIndex: 100 },
    { ...valid, resultsPerPage: 200 }, { ...valid, totalResults: 99 },
    { ...valid, totalResults: 101, resultsPerPage: 101, vulnerabilities: [...rows, cve('CVE-2026-10100')] }]) {
    const store = fixture(); store[nvdName] = [bad];
    assert.throws(() => run('02-normalize.js', store), /NVD/);
  }
});

test('來源端僅查首次公布時間，不再查修改時間', () => {
  const params = workflow.nodes.find(n => n.name === nvdName).parameters.queryParameters.parameters;
  assert.equal(params.find(p => p.name === 'pubStartDate')?.value, '={{ $json.nvdStart }}');
  assert.equal(params.find(p => p.name === 'pubEndDate')?.value, '={{ $json.nvdEnd }}');
  assert(!params.some(p => p.name.startsWith('lastMod')));
});

test('只納入近 30 小時首次公布且有有效 CWE 的 CVE；KEV 不補入舊資料', () => {
  const store = fixture();
  const rows = Array.from({ length: 9 }, (_, i) => cve(`CVE-2026-${20000 + i}`));
  rows.forEach(row => { row.cve.published = '2026-10-15T12:00:00.000'; });
  rows[1].cve.published = '2020-01-01T00:00:00.000';
  rows[1].cve.lastModified = '2026-10-15T12:00:00.000';
  rows[2].cve.weaknesses = [];
  rows[3].cve.weaknesses = [{ description: [{ value: 'NVD-CWE-noinfo' }, { value: 'NVD-CWE-Other' }, { value: 'CWE-invalid' }] }];
  rows[4].cve.published = 'invalid';
  delete rows[5].cve.published;
  rows[6].cve.published = '2026-10-16T00:00:00.000Z';
  rows[7].cve.published = win.startUtc;
  rows[8].cve.published = win.endUtc;
  store[nvdName][0] = { totalResults: rows.length, startIndex: 0, resultsPerPage: 100, vulnerabilities: rows };
  prepare(store); const prepared = store['整理漏洞與 Gemini 輸入'];
  assert.deepEqual(prepared.records.map(r => r.id).sort(), ['CVE-2026-20000', 'CVE-2026-20007', 'CVE-2026-20008']);
  assert.equal(prepared.rawNvdTotal, 9);
  const prompt = prepared.geminiRequest.contents[0].parts[0].text;
  for (const row of rows.slice(1, 7)) assert(!prompt.includes(row.cve.id));
  const output = run('03-report.js', store, response(store)); const report = JSON.parse(output.jsonText);
  assert.equal(report.coverage.filter.dateField, 'published');
  assert.equal(report.coverage.filter.requiresCwe, true);
  assert(report.records.every(r => r.cwes.length > 0));
  assert(output.markdown.includes('首次公布'));
  assert(!output.markdown.includes('KEV 補入'));
});

test('零筆符合時直接產生日報，工作流分支跳過 Gemini', () => {
  const store = fixture();
  store[nvdName][0].vulnerabilities.forEach(r => { r.cve.weaknesses = []; });
  prepare(store);
  assert.equal(store['整理漏洞與 Gemini 輸入'].selectedIds.length, 0);
  const output = run('03-report.js', store);
  const report = JSON.parse(output.jsonText);
  assert.equal(report.stats.analyzedCount, 0); assert.equal(report.stats.totalRecords, 0);
  assert(report.executiveSummaryZh.includes('未呼叫 Gemini'));
  const branch = workflow.nodes.find(n => n.name === '有符合條件的情報');
  assert.equal(branch?.type, 'n8n-nodes-base.if');
  const condition = branch.parameters.conditions.conditions[0];
  assert.equal(condition.operator.type, 'number'); assert.equal(condition.operator.operation, 'gt');
  const count = json => new Function('$json', `return (${condition.leftValue.slice(3, -2)});`)(json);
  assert(!(count({ selectedIds: [], cweGuideTargets: [] }) > condition.rightValue));
  assert(count({ selectedIds: ['CVE-2026-12345'], cweGuideTargets: [] }) > condition.rightValue);
  assert(count({ selectedIds: [], cweGuideTargets: ['CWE-506'] }) > condition.rightValue);
  assert.equal(workflow.connections['整理漏洞與 Gemini 輸入'].main[0][0].node, branch.name);
  assert.equal(workflow.connections[branch.name].main[0][0].node, 'Gemini 資安分析');
  assert.equal(workflow.connections[branch.name].main[1][0].node, '產生 MD 與 JSON');
});
