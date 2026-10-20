// n8n Code node - Run Once for All Items
const prepared = $('整理漏洞與 Gemini 輸入').first().json;
const guideTargets = prepared.cweGuideTargets || [];
let parsed = { executiveSummaryZh: '本次未取得符合關注技術、近 30 小時首次公布且有有效 CWE 的情報；未呼叫 Gemini。', analyses: [], cweGuides: [] };
if (prepared.selectedIds.length + guideTargets.length > 0) {
  const api = $input.first().json;
  if (api?.candidates?.[0]?.finishReason !== 'STOP') throw new Error('Gemini 未正常完成分析，停止發布');
  const texts = (api.candidates?.[0]?.content?.parts || []).map(p => p.text).filter(Boolean);
  if (!texts.length) throw new Error('Gemini 沒有回傳可用文字，停止發布');
  try { parsed = JSON.parse(texts.join('').trim()); }
  catch (e) { throw new Error(`Gemini JSON 解析失敗：${e.message}`); }
}
if (!parsed || !Array.isArray(parsed.analyses) || !Array.isArray(parsed.cweGuides) ||
    typeof parsed.executiveSummaryZh !== 'string' || !parsed.executiveSummaryZh.trim()) {
  throw new Error('Gemini JSON 結構或摘要無效，停止發布');
}
const isText = v => typeof v === 'string' && Boolean(v.trim());
const isNullableText = v => v === null || isText(v);
const allow = new Set(prepared.selectedIds);
const analyses = new Map();
for (const a of parsed.analyses) {
  if (!a || !allow.has(a.id) || analyses.has(a.id) ||
      !['可能相關', '較低相關', '無法判定'].includes(a.relevance) ||
      !['P0', 'P1', 'P2', 'P3'].includes(a.priority) ||
      !['summaryZh', 'reasonZh', 'actionZh', 'product'].every(k => isText(a[k])) ||
      typeof a.isCompanyProduct !== 'boolean' ||
      !['fixVersionZh', 'fixQuoteEn', 'fixQuoteZh', 'kevActionZh'].every(k => isNullableText(a[k]))) {
    throw new Error('Gemini 分析有未知或重複 ID、無效欄位，停止發布');
  }
  // Only accept analysis fields; AI must never overwrite official source facts.
  const { id, summaryZh, relevance, priority, reasonZh, actionZh, product, isCompanyProduct, fixVersionZh, fixQuoteEn, fixQuoteZh, kevActionZh } = a;
  analyses.set(id, { summaryZh, relevance, priority, reasonZh, actionZh, product: product.trim(), isCompanyProduct,
    fixVersionZh, fixQuoteEn, fixQuoteZh, kevActionZh });
}
if (analyses.size !== allow.size) throw new Error('Gemini 缺少被選取的 CVE 分析，停止發布');
const targetSet = new Set(guideTargets);
const guides = new Map();
for (const g of parsed.cweGuides) {
  if (!g || !targetSet.has(g.cwe) || guides.has(g.cwe) || !['nameZh', 'riskZh', 'handlingZh'].every(k => isText(g[k]))) {
    throw new Error('Gemini CWE 說明有未知或重複 CWE、無效欄位，停止發布');
  }
  guides.set(g.cwe, { cwe: g.cwe, nameZh: g.nameZh, riskZh: g.riskZh, handlingZh: g.handlingZh });
}
const cweGuides = guideTargets.filter(cwe => guides.has(cwe)).map(cwe => ({ ...guides.get(cwe),
  nameEn: prepared.cweInfo?.[cwe]?.nameEn ?? null, owasp: prepared.cweInfo?.[cwe]?.owasp ?? [] }));
const normalizeSpace = text => String(text).replace(/\s+/g, ' ').trim();
// 修補版本：GitHub 公告取官方欄位；NVD 須有逐字出現在官方描述中的摘句，且版本號都在摘句內。
function isFixVerified(record, analysis) {
  if (record.advisoryType === 'reviewed' && record.patchedVersions?.length) return true;
  if (record.sourceType !== 'NVD' || !analysis?.fixQuoteEn || !analysis.fixVersionZh) return false;
  const quote = normalizeSpace(analysis.fixQuoteEn);
  const versions = analysis.fixVersionZh.match(/\d+(?:\.\d+)+/g) || [];
  // 版本號要完整相符：1.22 或 22.4 不能冒充摘句中的 1.22.4。
  const quoteVersions = new Set(quote.match(/\d+(?:\.\d+)+/g) || []);
  return normalizeSpace(record.descriptionEn || '').includes(quote) && versions.length > 0 && versions.every(v => quoteVersions.has(v));
}
// 分類：必做、例行更新涵蓋、知悉即可。
function classify(r) {
  if (r.advisoryType === 'malware') return 'must_do';
  if (r.advisoryType === 'reviewed' && r.patchedVersions?.length) return 'must_do';
  const companyNvd = r.sourceType === 'NVD' && r.analysisStatus === 'ai_analyzed' && r.isCompanyProduct === true &&
    !r.disputed && !r.vendorManaged;
  if (companyNvd && (r.isKev || (r.fixVerified && !r.routine))) return 'must_do';
  if (r.routine && !r.isKev && r.isCompanyProduct !== false) return 'routine';
  return 'fyi';
}
const records = prepared.records.map(r => {
  const a = analyses.get(r.id);
  const record = a ? { ...r, ...a, analysisStatus: 'ai_analyzed', inventoryImpactConfirmed: false }
    : { ...r, summaryZh: null, relevance: '無法判定', priority: null, reasonZh: null, actionZh: null,
        inventoryImpactConfirmed: false, product: null, isCompanyProduct: null,
        fixVersionZh: null, fixQuoteEn: null, fixQuoteZh: null, kevActionZh: null };
  // GitHub 公告以套件名稱分組；未經 AI 的合併紀錄也退回套件名稱。
  if (r.sourceType === 'GHSA' || !record.product) record.product = r.packages?.length ? r.packages.join('、') : record.product;
  record.fixVerified = isFixVerified(r, a);
  record.actionType = classify(record);
  return record;
});
const countType = type => records.filter(r => r.actionType === type).length;
const stats = {
  totalNvdInWindow: prepared.rawNvdTotal,
  totalRecords: records.length,
  kevAddedInWindow: prepared.totalKevAdded,
  analyzedCount: analyses.size,
  unanalyzedCount: records.length - analyses.size,
  selectedButNotAnalyzed: prepared.selectedIds.length - analyses.size,
  possiblyRelevantAnalyzed: records.filter(r => r.analysisStatus === 'ai_analyzed' && r.relevance === '可能相關').length,
  mustDoCount: countType('must_do'), routineCount: countType('routine'), fyiCount: countType('fyi'),
  cweGuidesMissing: guideTargets.length - cweGuides.length,
};
const d = prepared.window.dateTW;
// 依使用者要求，日報與網站不另外說明是否部分蒐集；完整的蒐集狀態保留在 coverage.nvd／coverage.ghsa 供程式判讀。
const report = {
  schemaVersion: 1, date: d, generatedAt: new Date().toISOString(),
  timeZone: 'Asia/Taipei', model: PUBLIC_CONFIG.model,
  coverage: { fromUtc: prepared.window.startUtc, toUtc: prepared.window.endUtc,
    sources: ['NVD CVE API 2.0', 'CISA KEV JSON', 'GitHub Advisory Database'],
    filter: { type: 'keywordSearch', keywords: prepared.window.companyKeywords, dateField: 'published', requiresCwe: true },
    nvd: prepared.nvdCoverage, ghsa: prepared.ghsaCoverage,
    note: `NVD 每個關鍵字取得首頁最多 100 筆，依 KEV、CVSS、修補參考與公布時間保留 10 筆（限已取得的首頁 100 筆，來源超過 100 筆時不代表全體中最重要的 10 筆）；僅納入近 30 小時首次公布、具有有效 CWE 的關注技術 CVE，排除舊漏洞更新及缺少 CWE 的資料；之後才補 CWE 或未寫產品名稱的情報可能漏收。npm 套件情報來自 GitHub Advisory，只涵蓋設定清單內的套件，不含間接相依。篩選後最多 35 筆交由 AI 分析，其他保留來源欄位；不代表使用環境已受漏洞影響。` },
  stats, executiveSummaryZh: parsed.executiveSummaryZh.slice(0, 1500),
  actionPlan: null, cweGuides, records,
};
// 必做清單：同產品合併成一張卡片。
const AUDIENCE_ORDER = ['全員電腦', '伺服器管理者', '開發者'];
const KIND_ORDER = { malware: 0, kev: 1, update: 2 };
function buildActionPlan(list) {
  const groups = new Map();
  for (const r of list.filter(x => x.actionType === 'must_do')) {
    const kind = r.advisoryType === 'malware' ? 'malware' : r.isKev ? 'kev' : 'update';
    const product = String(r.product ?? r.id).trim();
    const key = `${kind}|${product.toLowerCase()}`;
    if (!groups.has(key)) groups.set(key, { kind, product, audience: [], fixVersions: [], owasp: [], recordIds: [], maxCvss: -1 });
    const g = groups.get(key);
    g.recordIds.push(r.id);
    g.audience = AUDIENCE_ORDER.filter(a => g.audience.includes(a) || (r.audience || []).includes(a));
    g.owasp = [...new Set([...g.owasp, ...(r.owasp || [])])].sort();
    const versions = kind === 'malware' || !r.fixVerified ? [] : r.patchedVersions?.length ? r.patchedVersions : [r.fixVersionZh];
    for (const v of versions) if (v && !g.fixVersions.includes(v)) g.fixVersions.push(v);
    g.maxCvss = Math.max(g.maxCvss, r.cvss ?? -1);
  }
  const mustDo = [...groups.values()]
    .sort((a, b) => KIND_ORDER[a.kind] - KIND_ORDER[b.kind] || b.recordIds.length - a.recordIds.length ||
      b.maxCvss - a.maxCvss || a.product.localeCompare(b.product))
    .map(({ maxCvss, ...item }) => item);
  const routineByKeyword = {};
  for (const r of list.filter(x => x.actionType === 'routine')) {
    for (const keyword of r.matchedKeywords || []) routineByKeyword[keyword] = (routineByKeyword[keyword] || 0) + 1;
  }
  // 因 AI 分析上限未判定、但可能成為必做的 NVD 紀錄需要揭露，避免「沒有必做」被誤讀。
  const unanalyzedCandidates = list.filter(r => r.actionType !== 'must_do' && r.analysisStatus !== 'ai_analyzed' &&
    r.sourceType === 'NVD' && (r.isKev || (!r.routine && !r.vendorManaged && !r.disputed))).length;
  return { mustDo, routineCount: stats.routineCount, routineByKeyword, fyiCount: stats.fyiCount, unanalyzedCandidates };
}
report.actionPlan = buildActionPlan(records);
const flat = v => String(v ?? '來源未涵蓋').replace(/[\r\n\t]+/g, ' ').replace(/</g, '&lt;').replace(/>/g, '&gt;').trim();
const owaspLabel = code => `${code} ${OWASP_2025_CATEGORIES[code] || ''}`.trim();
const byId = new Map(records.map(r => [r.id, r]));
const guideMap = new Map(cweGuides.map(g => [g.cwe, g]));
const cardTitle = item => item.kind === 'malware' ? `${item.product} 出現惡意版本`
  : item.kind === 'kev' ? `處理 ${item.product} 已知被利用漏洞` : `更新 ${item.product}`;
const lines = [
  `# 資安戰情室｜${d}`,
  // 開頭資訊用清單，避免連續的引用行在 Markdown 裡被併成同一段。
  '', `> - 產生時間：${report.generatedAt}（UTC）｜模型：${report.model}`,
  `> - 情報視窗：${report.coverage.fromUtc} ～ ${report.coverage.toUtc}`,
  '> - 注意：此報告是外部情報篩選，不代表使用環境已受影響。實際曝險須比對產品版本與資產清單。',
  '', '## 今天要做的事', '',
];
if (!report.actionPlan.mustDo.length) lines.push('今天沒有必做項目：沒有符合條件的更新，不代表使用環境沒有風險。', '');
for (const item of report.actionPlan.mustDo) {
  const items = item.recordIds.map(id => byId.get(id));
  const unique = list => [...new Set(list)];
  lines.push(`### ${flat(cardTitle(item))}`, '');
  if (item.kind === 'malware') {
    const affected = unique(items.flatMap(r => r.affectedVersions || []));
    lines.push(`1. 檢查各專案 lockfile 是否裝到受影響版本（${affected.length ? affected.map(flat).join('、') : '來源未涵蓋'}）`,
      '2. 裝到的機器更換其上的金鑰與密碼', '3. 更新到安全版本', '');
  } else {
    lines.push(`- 更新到：${item.fixVersions.length ? item.fixVersions.map(flat).join('、') : '請見廠商公告'}`);
  }
  lines.push(`- 誰要處理：${item.audience.join('、') || '來源未涵蓋'}`,
    `- OWASP：${item.owasp.length ? item.owasp.map(owaspLabel).join('、') : '不在 OWASP Top 10:2025 對照範圍'}`);
  lines.push(...unique(items.filter(r => r.fixVerified && r.sourceType === 'NVD' && r.fixQuoteEn && !r.patchedVersions?.length)
    .map(r => `- 官方原文：「${flat(r.fixQuoteEn)}」（中譯：${flat(r.fixQuoteZh)}）`)));
  if (item.kind === 'kev') {
    lines.push(...unique(items.filter(r => r.isKev).map(r =>
      `- CISA 要求：${flat(r.kevRequiredAction)}（中譯：${flat(r.kevActionZh)}）`)));
    lines.push(`- 列入 KEV：${unique(items.map(r => r.kevDateAdded).filter(Boolean)).join('、') || '來源未涵蓋'}`);
    const advisories = unique(items.flatMap(r => r.vendorAdvisoryUrls || []));
    lines.push(`- 廠商公告：${advisories.length ? advisories.join('、') : '來源未涵蓋，請查官方來源'}`);
  }
  for (const cwe of unique(items.flatMap(r => r.cwes))) {
    const g = guideMap.get(cwe);
    lines.push(g ? `- ${cwe} ${flat(g.nameZh)}：風險：${flat(g.riskZh)}；處理：${flat(g.handlingZh)}（AI 說明，未經人工確認）`
      : `- ${cwe}：AI 未提供說明，請參考 MITRE 定義`);
  }
  lines.push(`- 涵蓋：${item.recordIds.join('、')}`, `- 官方來源：${unique(items.map(r => r.sourceUrl)).join('、')}`, '');
}
if (report.actionPlan.unanalyzedCandidates) {
  lines.push(`另有 ${report.actionPlan.unanalyzedCandidates} 筆可能必做的情報因 AI 分析上限未判定，列於知悉即可。`, '');
}
const routineParts =Object.entries(report.actionPlan.routineByKeyword).map(([keyword, count]) => `${flat(keyword)} ${count}`);
lines.push('## 例行更新涵蓋', '',
  stats.routineCount
    ? `本次例行更新涵蓋 ${stats.routineCount} 則（${routineParts.join('、')}），多數由系統例行更新修補，不逐則列出；若為第三方軟體請另行確認，列入 KEV 者已單獨列在上方。`
    : '本次沒有例行更新涵蓋的情報。',
  '', '## 今日摘要', '', flat(report.executiveSummaryZh), '',
  '## 情報統計', '',
  `- NVD 關注技術查詢實際取得：${stats.totalNvdInWindow} 筆（近 30 小時首次公布、跨詞去重，含篩選前資料）`,
  `- 篩選後保留的情報：${stats.totalRecords} 筆（含 GitHub Advisory）`,
  `- 必做 ${stats.mustDoCount} 則、例行更新 ${stats.routineCount} 則、知悉即可 ${stats.fyiCount} 則`,
  `- 上述情報中最近新增 KEV：${stats.kevAddedInWindow} 筆（以日期範圍篩選）`,
  `- AI 分析：${stats.analyzedCount} 筆；其餘 ${stats.unanalyzedCount} 筆保留原始資料`,
  `- AI 分析且可能與關注技術相關：${stats.possiblyRelevantAnalyzed} 筆（非確定受影響）`,
  '', '## 知悉即可', '');
const fyi = records.filter(r => r.actionType === 'fyi');
if (!fyi.length) lines.push('本次沒有知悉即可的情報。');
for (const r of fyi) {
  const what = r.product || (r.matchedKeywords || []).join('/') || (r.packages || []).join('/') || '來源未涵蓋';
  lines.push(`- ${r.id}｜${flat(what)}｜${r.cwes.length ? r.cwes.join(', ') : '來源未涵蓋'}｜${r.sourceUrl}`);
}
lines.push('', '## 資料範圍與限制', '',
  `- 關注技術查詢關鍵字：${prepared.window.companyKeywords.map(flat).join('、')}。`,
  '- NVD 描述未寫產品名稱、只在 CPE 出現或僅列相依套件名稱時，來源端關鍵字查詢可能漏收；技術命中仍須確認實際使用版本。',
  '- NVD 以最近 30 小時首次公布時間查詢；舊漏洞更新、尚未收錄或尚無有效 CWE 的 CVE 不納入，也不另外補入 KEV 舊漏洞。之後才補 CWE 的資料可能漏收。',
  '- 每日查詢有 6 小時重疊，同一 CVE 可能跨日重複；CISA KEV 僅提供日期，可能涵蓋起點當日較早的資料。',
  '- CWE 僅收錄官方 NVD 在 CVE 弱點欄位提供的有效 CWE 編號；OWASP 類別依 OWASP Top 10:2025 官方對照表標示。',
  '- npm 套件情報來自 GitHub Advisory，只涵蓋設定清單內的套件，不含間接相依；套件清單需手動維護。',
  '- 必做由程式依官方欄位判定；「屬於關注產品」與修補版本摘句由 AI 協助判讀，未經人工確認。',
  '- NVD 每個關鍵字取得首頁最多 100 筆，依重要性保留 10 筆（限已取得的首頁，不代表全體中最重要的 10 筆）。',
  '- 高風險判斷是「建議先調查」而非「已確認影響使用環境」。',
  '- 完整情報請見同日 JSON 檔；需要新增廠商公告來源時應另增節點。',
  '', '## 官方來源', '',
  '- NVD CVE API：https://nvd.nist.gov/developers/vulnerabilities',
  '- CISA KEV：https://github.com/cisagov/kev-data',
  '- GitHub Advisory Database：https://github.com/advisories',
  '- OWASP Top 10:2025：https://top10.owasp.org/2025/',
  '- CWE：https://cwe.mitre.org/',
  '');
// Telegram 純文字通知；網址來自公開設定，不依賴特定主機。
const DASHBOARD_URL = PUBLIC_CONFIG.dashboardUrl;
const CHAT_MAX_ITEMS = 10;
// 產品名稱可能來自 AI 或外部公告；角括號換成全形，避免被解析成 <網址|文字> 這類連結語法。
const chatFlat = v => String(v ?? '來源未涵蓋').replace(/\s+/g, ' ').replace(/</g, '＜').replace(/>/g, '＞').trim();
const mustDo = report.actionPlan.mustDo;
const chatLines = [`資安戰情室｜${d}`, '',
  mustDo.length ? `今天要做的事：${mustDo.length} 項` : '今天沒有必做項目：沒有符合條件的更新，不代表使用環境沒有風險。',
  ...mustDo.slice(0, CHAT_MAX_ITEMS).map(item => `• ${chatFlat(cardTitle(item))}（${item.audience.join('、') || '來源未涵蓋'}）`)];
if (mustDo.length > CHAT_MAX_ITEMS) chatLines.push(`…另有 ${mustDo.length - CHAT_MAX_ITEMS} 項，請見儀表板`);
if (report.actionPlan.unanalyzedCandidates) {
  chatLines.push(`另有 ${report.actionPlan.unanalyzedCandidates} 筆可能必做的情報因 AI 分析上限未判定。`);
}
chatLines.push('', `例行更新 ${stats.routineCount} 則、知悉即可 ${stats.fyiCount} 則`,
  '此為外部情報篩選，不代表使用環境已受影響。', `儀表板：${DASHBOARD_URL}`);
// Telegram sendMessage 上限 4096；截短摘要但保留完整網址，避免切斷 emoji。
let chatText = chatLines.join('\n');
if (chatText.length > 4000) {
  chatText = chatText.slice(0, 3400).replace(/[\uD800-\uDBFF]$/, '') + `\n…完整內容請見儀表板：${DASHBOARD_URL}`;
}
return [{ json: {
  reportDate: d,
  reportSubdir: `${d.slice(0, 4)}/${d.slice(5, 7)}`,
  markdown: lines.join('\n'),
  jsonText: JSON.stringify(report, null, 2),
  chatText,
  stats,
} }];
