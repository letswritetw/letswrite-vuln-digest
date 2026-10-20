const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');

// 保留原建置器的 UUID v5（URL namespace），避免匯入後節點 ID 改變。
function nodeId(name) {
  const bytes = createHash('sha1')
    .update(Buffer.from('6ba7b8119dad11d180b400c04fd430c8', 'hex'))
    .update(`soc:${name}`, 'utf8').digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function validateConfig(config) {
  const fail = () => { throw new Error('config.json 設定無效：請檢查關鍵字、套件、模型、網站網址與 Telegram 設定。'); };
  const text = value => typeof value === 'string' && value.trim() === value && value.length > 0 && !/[\r\n\u0000]/.test(value);
  const audiences = new Set(['全員電腦', '伺服器管理者', '開發者']);
  const fields = new Set(['model', 'dashboardUrl', 'telegramEnabled', 'telegramChatId', 'keywords', 'npmPackages']);
  if (!config || Object.keys(config).some(key => !fields.has(key)) ||
      !Array.isArray(config.keywords) || !config.keywords.length || config.keywords.length > 50 ||
      config.keywords.some(p => !p || !text(p.keyword) || p.keyword.length > 80 || p.keyword !== p.keyword.toLowerCase() ||
        Object.keys(p).some(key => !['keyword', 'audience', 'routine', 'vendorManaged', 'aliases'].includes(key)) ||
        !Array.isArray(p.audience) || !p.audience.length || p.audience.some(a => !audiences.has(a)) ||
        typeof p.routine !== 'boolean' || typeof p.vendorManaged !== 'boolean' ||
        !Array.isArray(p.aliases) || p.aliases.some(a => !text(a) || a.length > 80)) ||
      new Set(config.keywords.map(p => p.keyword)).size !== config.keywords.length ||
      !Array.isArray(config.npmPackages) || !config.npmPackages.length || config.npmPackages.length > 100 ||
      config.npmPackages.some(p => typeof p !== 'string' || !/^(?:@[a-z0-9._-]+\/)?[a-z0-9][a-z0-9._-]*$/.test(p)) ||
      new Set(config.npmPackages).size !== config.npmPackages.length ||
      typeof config.model !== 'string' || !/^[a-z0-9][a-z0-9._-]{0,99}$/.test(config.model) ||
      typeof config.telegramEnabled !== 'boolean' || typeof config.telegramChatId !== 'string' ||
      !/^(?:-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})?$/.test(config.telegramChatId) ||
      (config.telegramEnabled && !config.telegramChatId)) fail();
  try {
    const url = new URL(config.dashboardUrl);
    if (!text(config.dashboardUrl) || config.dashboardUrl.length > 500 ||
        !['http:', 'https:'].includes(url.protocol) || url.username || url.password) fail();
  } catch { fail(); }
  return config;
}
function readConfig() {
  let config;
  try { config = JSON.parse(fs.readFileSync(path.join(__dirname, 'config.json'), 'utf8')); }
  catch { throw new Error('config.json 設定讀取失敗：請確認檔案存在且是有效 JSON。'); }
  return validateConfig(config);
}

// n8n Code 節點無法引用其他檔案；共用資料表在建置時串接到同一個節點。
const CODE_PARTS = {
  '02-normalize.js': ['owasp-2025.js', '02-normalize.js'],
  '03-report.js': ['owasp-2025.js', '03-report.js'],
};
function scriptSource(file, config = readConfig()) {
  const prefix = ['01-window.js', '03-report.js'].includes(file) ? `const PUBLIC_CONFIG = ${JSON.stringify(validateConfig(config))};\n` : '';
  return prefix + (CODE_PARTS[file] || [file]).map(name => fs.readFileSync(path.join(__dirname, 'scripts', name), 'utf8')).join('\n');
}

function createWorkflow(config = readConfig()) {
  validateConfig(config);
  const code = file => scriptSource(file, config);
  // 固定 ID：容器啟動時重新匯入會覆蓋同一份工作流，不會產生重複副本。
  const workflow = {
    id: 'cweDailyReport01', name:'資安戰情室｜NVD + CISA KEV → Gemini → MD + JSON', nodes: [], connections: {},
    settings: { executionOrder: 'v1', timezone: 'Asia/Taipei' }, active: false, pinData: {}, tags: [],
  };
  function node(name, type, parameters, x, typeVersion) {
    const entry = { parameters, id: nodeId(name), name, type: `n8n-nodes-base.${type}`, typeVersion, position: [x, 200] };
    workflow.nodes.push(entry);
    return entry;
  }
  node('每天 07:00', 'scheduleTrigger', { rule: { interval: [{ field: 'cronExpression', expression: '0 7 * * *' }] } }, 200, 1.2);
  node('建立時間區間', 'code', { mode: 'runOnceForAllItems', jsCode: code('01-window.js') }, 480, 2);
  node('逐項查詢關注技術', 'splitInBatches', { batchSize: 1, options: {} }, 620, 3);
  node('取得 NVD 30h CVE', 'httpRequest', {
    method: 'GET', url: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    sendQuery: true, specifyQuery: 'keypair', queryParameters: { parameters: [
      { name: 'pubStartDate', value: '={{ $json.nvdStart }}' },
      { name: 'pubEndDate', value: '={{ $json.nvdEnd }}' },
      { name: 'keywordSearch', value: '={{ $json.nvdKeyword }}' },
      { name: 'resultsPerPage', value: '100' }, { name: 'startIndex', value: '0' },
    ] },
    options: { timeout: 90000, response: { response: { responseFormat: 'json' } } },
  }, 760, 4.2).position[1] = 480;
  node('收集本次 NVD 分頁', 'code', { mode: 'runOnceForAllItems', jsCode: code('02-collect.js') }, 1040, 2).position[1] = 480;
  node('查詢間隔 6 秒', 'wait', { resume: 'timeInterval', amount: 6, unit: 'seconds' }, 1320, 1.1).position[1] = 480;
  node('彙整關注查詢', 'code', {
    mode: 'runOnceForAllItems', jsCode: 'return [{ json: { queries: $input.all().map(item => item.json) } }];',
  }, 760, 2);
  node('取得 CISA KEV', 'httpRequest', {
    method: 'GET', url: 'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json',
    options: { timeout: 90000, response: { response: { responseFormat: 'json' } } },
  }, 1040, 4.2).executeOnce = true;
  // 回應以文字取得：JSON 陣列會被 n8n 拆成多個 item，空陣列時下游不執行。
  for (const [name, type, x] of [['取得 GitHub 套件公告', 'reviewed', 1110], ['取得 GitHub 惡意套件', 'malware', 1180]]) {
    const entry = node(name, 'httpRequest', {
      method: 'GET', url: 'https://api.github.com/advisories',
      sendQuery: true, specifyQuery: 'keypair', queryParameters: { parameters: [
        { name: 'ecosystem', value: 'npm' }, { name: 'type', value: type },
        { name: 'affects', value: "={{ $('建立時間區間').first().json.ghsaAffects }}" },
        { name: 'published', value: "={{ $('建立時間區間').first().json.ghsaPublished }}" },
        { name: 'per_page', value: '100' },
      ] },
      sendHeaders: true, headerParameters: { parameters: [
        { name: 'Accept', value: 'application/vnd.github+json' },
        { name: 'X-GitHub-Api-Version', value: '2022-11-28' },
      ] },
      options: { timeout: 90000, response: { response: { responseFormat: 'text', outputPropertyName: 'data' } } },
    }, x, 4.2);
    entry.executeOnce = true;
    entry.position[1] = -40;
  }
  node('整理漏洞與 Gemini 輸入', 'code', { mode: 'runOnceForAllItems', jsCode: code('02-normalize.js') }, 1320, 2);
  node('有符合條件的情報', 'if', { conditions: {
    options: { caseSensitive: true, leftValue: '', typeValidation: 'strict', version: 1 },
    conditions: [{ id: nodeId('分析筆數條件'), leftValue: '={{ $json.selectedIds.length + $json.cweGuideTargets.length }}', rightValue: 0,
      operator: { type: 'number', operation: 'gt' } }], combinator: 'and',
  }, options: {} }, 1460, 2);
  node('Gemini 資安分析', 'httpRequest', {
    method: 'POST', url: `https://generativelanguage.googleapis.com/v1beta/models/${config.model}:generateContent`,
    authentication: 'genericCredentialType', genericAuthType: 'httpHeaderAuth',
    sendHeaders: true, headerParameters: { parameters: [{ name: 'Content-Type', value: 'application/json' }] },
    sendBody: true, specifyBody: 'json', jsonBody: '={{ JSON.stringify($json.geminiRequest) }}', options: { timeout: 120000 },
  }, 1600, 4.2);
  node('產生 MD 與 JSON', 'code', { mode: 'runOnceForAllItems', jsCode: code('03-report.js') }, 1880, 2);
  node('MD 轉檔', 'convertToFile', {
    operation: 'toText', sourceProperty: 'markdown', binaryPropertyName: 'data',
    options: { fileName: '={{ "security-daily-" + $json.reportDate + ".md" }}', encoding: 'utf8' },
  }, 2160, 1.1);
  node('寫入每日 MD', 'readWriteFile', {
    operation: 'write',
    fileName: '={{ "/files/reports/" + $("產生 MD 與 JSON").first().json.reportSubdir + "/security-daily-" + $("產生 MD 與 JSON").first().json.reportDate + ".md" }}',
    dataPropertyName: 'data', options: {},
  }, 2440, 1);
  node('載入報告 JSON', 'code', {
    mode: 'runOnceForAllItems', jsCode: "return [{ json: $('產生 MD 與 JSON').first().json }];",
  }, 2720, 2);
  node('每日 JSON 轉檔', 'convertToFile', {
    operation: 'toText', sourceProperty: 'jsonText', binaryPropertyName: 'data',
    options: { fileName: '={{ "security-daily-" + $json.reportDate + ".json" }}', encoding: 'utf8' },
  }, 3000, 1.1);
  node('寫入每日 JSON', 'readWriteFile', {
    operation: 'write',
    fileName: '={{ "/files/reports/" + $("產生 MD 與 JSON").first().json.reportSubdir + "/security-daily-" + $("產生 MD 與 JSON").first().json.reportDate + ".json" }}',
    dataPropertyName: 'data', options: {},
  }, 3280, 1);
  node('載入最新 JSON', 'code', {
    mode: 'runOnceForAllItems', jsCode: "return [{ json: $('產生 MD 與 JSON').first().json }];",
  }, 3560, 2);
  node('最新 JSON 轉檔', 'convertToFile', {
    operation: 'toText', sourceProperty: 'jsonText', binaryPropertyName: 'data',
    options: { fileName: 'latest.json', encoding: 'utf8' },
  }, 3840, 1.1);
  node('寫入 latest.json', 'readWriteFile', {
    operation: 'write', fileName: '/files/reports/latest.json', dataPropertyName: 'data', options: {},
  }, 4120, 1);
  // 三份檔案寫完才通知；Bot Token 在匯入後選用 Telegram API Credential，不寫入匯出檔。
  // 原生節點未設 parse_mode 會補 Markdown；統一跳脫 HTML，讓來源文字原樣顯示。
  const telegram = node('發送 Telegram 通知', 'telegram', {
    resource: 'message', operation: 'sendMessage', chatId: config.telegramChatId,
    text: '={{ $("產生 MD 與 JSON").first().json.chatText.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;") }}',
    additionalFields: { parse_mode: 'HTML', appendAttribution: false, disable_web_page_preview: true },
  }, 4400, 1.2);
  telegram.disabled = !config.telegramEnabled;
  Object.assign(telegram, { retryOnFail: true, maxTries: 3, waitBetweenTries: 5000 });
  for (let i = 0; i < workflow.nodes.length - 1; i++) {
    workflow.connections[workflow.nodes[i].name] = { main: [[{ node: workflow.nodes[i + 1].name, type: 'main', index: 0 }]] };
  }
  workflow.connections['逐項查詢關注技術'] = { main: [
    [{ node: '彙整關注查詢', type: 'main', index: 0 }],
    [{ node: '取得 NVD 30h CVE', type: 'main', index: 0 }],
  ] };
  workflow.connections['查詢間隔 6 秒'] = { main: [[{ node: '逐項查詢關注技術', type: 'main', index: 0 }]] };
  workflow.connections['有符合條件的情報'] = { main: [
    [{ node: 'Gemini 資安分析', type: 'main', index: 0 }],
    [{ node: '產生 MD 與 JSON', type: 'main', index: 0 }],
  ] };
  for (const entry of workflow.nodes) {
    if (entry.type === 'n8n-nodes-base.httpRequest') Object.assign(entry, { retryOnFail: true, maxTries: 3, waitBetweenTries: 5000 });
  }
  return workflow;
}

if (require.main === module) {
  const workflow = createWorkflow();
  const file = path.join(__dirname, 'workflow', 'security-intel-gemini.json');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(workflow, null, 2), 'utf8');
  console.log(`節點：${workflow.nodes.length}；檔案大小：${fs.statSync(file).size} bytes`);
}

module.exports = { createWorkflow, scriptSource, validateConfig };
