import http from 'node:http';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const maxBytes = 10 * 1024 * 1024;
const mime = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.woff2': 'font/woff2' };
const isDate = value => /^\d{4}-\d{2}-\d{2}$/.test(value) &&
  !Number.isNaN(Date.parse(`${value}T00:00:00Z`)) && new Date(`${value}T00:00:00Z`).toISOString().slice(0, 10) === value;
const problem = (status, message) => Object.assign(new Error(message), { status });
const strings = value => Array.isArray(value) && value.every(item => typeof item === 'string');
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const RECORD_ID = /^(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$/;
const AUDIENCES = ['全員電腦', '伺服器管理者', '開發者'];
const count = value => Number.isInteger(value) && value >= 0;
const optional = (value, check) => value == null || check(value);
const textOrNull = value => value === null || typeof value === 'string';
const listOf = (value, allowed) => Array.isArray(value) && value.every(item => allowed(item));
const owaspCode = item => typeof item === 'string' && /^A(0[1-9]|10):2025$/.test(item);

// 必做清單相關欄位全為選填（舊報告沒有），出現時型別必須正確。
function validateExtras(report) {
  const ids = new Set(report.records.map(record => record.id));
  const recordOk = record =>
    optional(record.sourceType, v => ['NVD', 'GHSA'].includes(v)) &&
    (record.advisoryType === undefined || [null, 'reviewed', 'malware'].includes(record.advisoryType)) &&
    optional(record.actionType, v => ['must_do', 'routine', 'fyi'].includes(v)) &&
    optional(record.audience, v => listOf(v, item => AUDIENCES.includes(item))) &&
    optional(record.owasp, v => listOf(v, owaspCode)) &&
    ['patchedVersions', 'packages', 'affectedVersions', 'vendorAdvisoryUrls'].every(key => optional(record[key], strings)) &&
    ['routine', 'vendorManaged', 'disputed', 'fixVerified'].every(key => optional(record[key], v => typeof v === 'boolean')) &&
    (record.isCompanyProduct === undefined || record.isCompanyProduct === null || typeof record.isCompanyProduct === 'boolean') &&
    ['ghsaId', 'product', 'fixVersionZh', 'fixQuoteEn', 'fixQuoteZh', 'kevActionZh'].every(key => record[key] === undefined || textOrNull(record[key]));
  const plan = report.actionPlan;
  const planOk = plan == null || (object(plan) && Array.isArray(plan.mustDo) &&
    ['routineCount', 'fyiCount'].every(key => count(plan[key])) && optional(plan.unanalyzedCandidates, count) &&
    object(plan.routineByKeyword) && Object.values(plan.routineByKeyword).every(count) &&
    plan.mustDo.every(item => object(item) && ['update', 'kev', 'malware'].includes(item.kind) && typeof item.product === 'string' &&
      listOf(item.audience, a => AUDIENCES.includes(a)) && strings(item.fixVersions) && listOf(item.owasp, owaspCode) &&
      listOf(item.recordIds, id => ids.has(id))));
  const guides = report.cweGuides;
  const guidesOk = guides == null || (Array.isArray(guides) && new Set(guides.map(g => g?.cwe)).size === guides.length &&
    guides.every(g => object(g) && /^CWE-\d+$/.test(g.cwe || '') && ['nameZh', 'riskZh', 'handlingZh'].every(key => typeof g[key] === 'string') &&
      textOrNull(g.nameEn ?? null) && optional(g.owasp, v => listOf(v, owaspCode))));
  const ghsa = report.coverage.ghsa;
  const ghsaOk = ghsa == null || (object(ghsa) && ['complete', 'partial'].includes(ghsa.status) &&
    optional(ghsa.packages, strings) && ['reviewedCount', 'malwareCount'].every(key => optional(ghsa[key], count)));
  const queriesOk = (report.coverage.nvd?.queries || []).every(query =>
    optional(query.eligibleCount, count) && optional(query.keptCount, count)) && optional(report.coverage.nvd?.keepPerKeyword, count);
  const statsOk = ['mustDoCount', 'routineCount', 'fyiCount', 'cweGuidesMissing'].every(key => optional(report.stats[key], count)) &&
    (report.stats.mustDoCount == null || report.stats.mustDoCount === report.records.filter(r => r.actionType === 'must_do').length);
  if (!report.records.every(recordOk) || !planOk || !guidesOk || !ghsaOk || !queriesOk || !statsOk) {
    throw problem(422, '日報情報欄位損毀，請檢查 n8n 產出。');
  }
}

function validateReport(report, date) {
  if (report?.schemaVersion !== 1 || !isDate(report.date || '') || (date && report.date !== date) ||
      typeof report.generatedAt !== 'string' || !Number.isFinite(Date.parse(report.generatedAt)) ||
      typeof report.executiveSummaryZh !== 'string' || !Array.isArray(report.records) ||
      report.records.length > 10000 || !object(report.coverage) || !object(report.stats) ||
      !['totalNvdInWindow', 'totalRecords', 'kevAddedInWindow', 'analyzedCount', 'unanalyzedCount', 'selectedButNotAnalyzed', 'possiblyRelevantAnalyzed']
        .every(key => Number.isInteger(report.stats[key]) && report.stats[key] >= 0)) {
    throw problem(422, '日報格式損毀或版本不支援，請檢查 n8n 產出。');
  }
  const { coverage } = report;
  if (!['fromUtc', 'toUtc'].every(key => typeof coverage[key] === 'string' && Number.isFinite(Date.parse(coverage[key]))) ||
      (coverage.note != null && typeof coverage.note !== 'string') ||
      (coverage.sources != null && !strings(coverage.sources)) ||
      (coverage.filter != null && (!object(coverage.filter) ||
        (coverage.filter.keywords != null && !strings(coverage.filter.keywords)) ||
        (coverage.filter.dateField != null && !['published', 'lastModified'].includes(coverage.filter.dateField)) ||
        (coverage.filter.requiresCwe != null && typeof coverage.filter.requiresCwe !== 'boolean'))) ||
      (coverage.nvd != null && (!object(coverage.nvd) || !['complete', 'partial'].includes(coverage.nvd.status) ||
        (coverage.nvd.queries != null && (!Array.isArray(coverage.nvd.queries) || coverage.nvd.queries.some(query =>
          !object(query) || typeof query.keyword !== 'string' || typeof query.truncated !== 'boolean' ||
          !['totalResults', 'returnedCount'].every(key => Number.isInteger(query[key]) && query[key] >= 0))))))) {
    throw problem(422, '日報資料範圍欄位損毀，請檢查 n8n 產出。');
  }
  const ids = new Set();
  for (const record of report.records) {
    if (!RECORD_ID.test(record?.id || '') || ids.has(record.id) ||
        !Array.isArray(record.cwes) || !record.cwes.every(cwe => /^CWE-\d+$/.test(cwe)) ||
        !['ai_analyzed', 'not_analyzed'].includes(record.analysisStatus) ||
        (record.priority != null && !['P0', 'P1', 'P2', 'P3'].includes(record.priority)) ||
        ['cpes', 'matchedKeywords'].some(key => record[key] != null && !strings(record[key])) ||
        ['isKev', 'isNewKev', 'inventoryImpactConfirmed'].some(key => record[key] != null && typeof record[key] !== 'boolean') ||
        ['published', 'lastModified', 'descriptionEn', 'cvssVersion', 'kevDateAdded', 'kevVendor', 'kevProduct', 'kevRequiredAction', 'sourceUrl', 'kevUrl', 'summaryZh', 'relevance', 'reasonZh', 'actionZh']
          .some(key => record[key] != null && typeof record[key] !== 'string') ||
        (record.cvss != null && (typeof record.cvss !== 'number' || !Number.isFinite(record.cvss) || record.cvss < 0 || record.cvss > 10))) {
      throw problem(422, '日報情報欄位損毀，請檢查 n8n 產出。');
    }
    ids.add(record.id);
  }
  const analyzed = report.records.filter(record => record.analysisStatus === 'ai_analyzed').length;
  if (report.stats.totalRecords !== report.records.length || report.stats.analyzedCount !== analyzed ||
      report.stats.unanalyzedCount !== report.records.length - analyzed) {
    throw problem(422, '日報統計與情報筆數不一致，請重新產生完整日報。');
  }
  validateExtras(report);
  return report;
}

export function createDashboardServer({ reportsDir, distDir = path.join(here, 'dist') }) {
  // 只快取歷史檔案的驗證結果，避免每次查詢重讀三年份 JSON 內容。
  const historyChecks = new Map();

  async function safeFile(root, relative) {
    let realRoot;
    try { realRoot = await fs.realpath(root); }
    catch { throw problem(503, '資料目錄無法讀取，請管理者檢查掛載與權限。'); }
    const fullPath = await fs.realpath(path.join(realRoot, relative));
    const within = path.relative(realRoot, fullPath);
    if (within.startsWith('..') || path.isAbsolute(within)) throw problem(403, '不允許讀取此路徑。');
    const stat = await fs.stat(fullPath);
    if (!stat.isFile() || stat.size > maxBytes) throw problem(422, '檔案格式或大小不符合限制。');
    return { fullPath, stat };
  }

  async function datedFile(date, extension) {
    if (!isDate(date)) throw problem(400, '日期格式無效。');
    try { return await safeFile(reportsDir, `${date.slice(0, 4)}/${date.slice(5, 7)}/security-daily-${date}.${extension}`); }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      return safeFile(reportsDir, `security-daily-${date}.${extension}`);
    }
  }

  async function readReport(file, date) {
    let report;
    try { report = JSON.parse(await fs.readFile(file.fullPath, 'utf8')); }
    catch (error) {
      if (error instanceof SyntaxError) throw problem(422, '日報 JSON 尚未完整寫入或已損毀，請稍後重新整理。');
      throw error;
    }
    return validateReport(report, date);
  }

  async function history() {
    let entries;
    try { entries = await fs.readdir(reportsDir, { withFileTypes: true }); }
    catch { throw problem(503, '報告目錄無法讀取，請管理者檢查掛載與權限。'); }
    const candidates = new Set();
    const collect = names => {
      for (const entry of names) {
        const match = entry.isFile() && /^security-daily-(\d{4}-\d{2}-\d{2})\.json$/.exec(entry.name);
        if (match && isDate(match[1])) candidates.add(match[1]);
      }
    };
    collect(entries);
    for (const year of entries.filter(entry => entry.isDirectory() && /^\d{4}$/.test(entry.name))) {
      const months = await fs.readdir(path.join(reportsDir, year.name), { withFileTypes: true });
      for (const month of months.filter(entry => entry.isDirectory() && /^(0[1-9]|1[0-2])$/.test(entry.name))) {
        collect(await fs.readdir(path.join(reportsDir, year.name, month.name), { withFileTypes: true }));
      }
    }
    const dates = [];
    for (const date of [...candidates].sort().reverse()) {
      try {
        const file = await datedFile(date, 'json');
        const signature = `${file.fullPath}:${file.stat.mtimeMs}:${file.stat.ctimeMs}:${file.stat.size}`;
        if (historyChecks.get(date)?.signature !== signature) {
          let valid = true;
          try { await readReport(file, date); } catch (error) { if (error.status === 422) valid = false; else throw error; }
          historyChecks.set(date, { signature, valid });
        }
        if (historyChecks.get(date).valid) dates.push({ date });
      } catch (error) {
        if (error.code !== 'ENOENT' && error.status !== 403 && error.status !== 422) throw error;
      }
    }
    for (const date of historyChecks.keys()) if (!candidates.has(date)) historyChecks.delete(date);
    let latestDate = null;
    try { latestDate = (await readReport(await safeFile(reportsDir, 'latest.json'))).date; }
    catch (error) { if (error.code !== 'ENOENT' && error.status !== 422) throw error; }
    return { reports: dates, latestDate };
  }

  return http.createServer(async (req, res) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'none'");
    const send = (status, data, contentType = 'application/json; charset=utf-8') => {
      res.writeHead(status, { 'Content-Type': contentType });
      res.end(typeof data === 'string' ? data : JSON.stringify(data));
    };
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.setHeader('Allow', 'GET, HEAD'); send(405, { error: '儀表板僅供讀取。' }); return;
    }
    try {
      const rawPath = (req.url || '/').split('?')[0];
      if (/%2e|%2f|%5c|\\|\.\./i.test(rawPath)) throw problem(400, '不允許此路徑。');
      const url = new URL(req.url, 'http://localhost');
      if ([...url.searchParams.keys()].some(key => key !== 'download') ||
          (url.searchParams.has('download') && url.searchParams.get('download') !== '1')) throw problem(400, '查詢參數無效。');
      if (url.pathname === '/api/reports') { send(200, await history()); return; }
      const match = /^\/api\/reports\/(latest|\d{4}-\d{2}-\d{2})(\/markdown)?$/.exec(url.pathname);
      if (match) {
        const report = match[1] === 'latest'
          ? await readReport(await safeFile(reportsDir, 'latest.json'))
          : await readReport(await datedFile(match[1], 'json'), match[1]);
        const extension = match[2] ? 'md' : 'json';
        if (url.searchParams.has('download')) res.setHeader('Content-Disposition', `attachment; filename="security-daily-${report.date}.${extension}"`);
        if (match[2]) {
          const file = await datedFile(report.date, 'md');
          send(200, await fs.readFile(file.fullPath, 'utf8'), 'text/markdown; charset=utf-8');
        } else send(200, report);
        return;
      }
      if (url.pathname.startsWith('/api/')) throw problem(404, '找不到此 API。');
      const relative = url.pathname === '/' ? 'index.html' : decodeURIComponent(url.pathname).slice(1);
      const file = await safeFile(distDir, relative);
      const type = mime[path.extname(file.fullPath)];
      if (!type) throw problem(404, '找不到此資源。');
      const body = req.method === 'HEAD' ? undefined : await fs.readFile(file.fullPath);
      res.writeHead(200, { 'Content-Type': type });
      res.end(body);
    } catch (error) {
      const status = error.status || (error.code === 'ENOENT' ? 404 : 503);
      send(status, { error: error.status ? error.message : status === 404 ? '尚無此日報或檔案，請確認 n8n 已完成產出。' : '報告目錄暫時無法讀取，請聯絡管理者檢查掛載與權限。' });
    }
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const server = createDashboardServer({
    reportsDir: path.resolve(process.env.REPORTS_DIR || path.join(here, '../reports')),
  });
  const port = Number(process.env.PORT || 3030);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('PORT 設定無效。');
  server.listen(port, process.env.HOST || '127.0.0.1', () => console.log(`資安儀表板已啟動，埠號 ${port}。`));
}
