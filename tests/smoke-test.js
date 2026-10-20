// Offline test with synthetic CVE/KEV fixtures. DOES NOT call Gemini or NVD.
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const base = path.resolve(__dirname, '..');
const workflow = JSON.parse(fs.readFileSync(path.join(base, 'workflow/security-intel-gemini.json'),'utf8'));
const store = {};
const $ = name => ({
  first:() => ({json:Array.isArray(store[name]) ? store[name][0] : store[name]}),
  all:() => (Array.isArray(store[name]) ? store[name] : [store[name]]).map(json => ({json})),
});
function run(file, input = []) {
  const fn = new Function('$','$input',require('../build.js').scriptSource(file));
  return fn($,{first:()=>({json:input[0]})})[0].json;
}
store['建立時間區間'] = run('01-window.js');
store['建立時間區間'].companyKeywords = ['sql server'];
store['建立時間區間'].keywordProfiles = { 'sql server': { audience: ['伺服器管理者'], routine: false, vendorManaged: false, aliases: [] } };
Object.defineProperty(store, '彙整關注查詢', { get: () => ({ queries: [{ keyword: 'sql server', pages: [store['取得 NVD 30h CVE']] }] }) });
const date = store['建立時間區間'].startUtc.slice(0,10);
store['取得 NVD 30h CVE'] = {totalResults:2,startIndex:0,resultsPerPage:100,vulnerabilities:[
  {cve:{id:'CVE-2026-12345',published:store['建立時間區間'].endUtc,lastModified:new Date().toISOString(),vulnStatus:'Analyzed',
    descriptions:[{lang:'en',value:'A privilege escalation in Microsoft SQL Server.'}],
    metrics:{cvssMetricV31:[{cvssData:{baseScore:8.1,version:'3.1'}}]},
    weaknesses:[{description:[{value:'CWE-269'}]}], configurations:[{nodes:[{cpeMatch:[{vulnerable:true,criteria:'cpe:2.3:a:microsoft:sql_server:*:*:*:*:*:*:*:*'}]}]}]}}
  ,{cve:{id:'CVE-2026-54321',vulnStatus:'Analyzed',descriptions:[{lang:'en',value:'Another SQL Server example.'}],weaknesses:[]}}
]};
store['取得 GitHub 套件公告'] = {data:'[]'}; store['取得 GitHub 惡意套件'] = {data:'[]'};
store['取得 CISA KEV'] = {vulnerabilities:[
  {cveID:'CVE-2026-12345',dateAdded:date,vendorProject:'Microsoft',product:'SQL Server',requiredAction:'Apply mitigations.'},
  {cveID:'CVE-2025-98765',dateAdded:date,vendorProject:'Example vendor',product:'SQL Server',requiredAction:'Check vendor advisory.'}
]};
store['整理漏洞與 Gemini 輸入'] = run('02-normalize.js');
assert.strictEqual(store['整理漏洞與 Gemini 輸入'].records.length,1);
assert(!store['整理漏洞與 Gemini 輸入'].records.some(x=>x.id==='CVE-2025-98765'));
assert(store['整理漏洞與 Gemini 輸入'].records[0].isKev);
assert(store['整理漏洞與 Gemini 輸入'].records.find(x=>x.id==='CVE-2026-12345').cwes.includes('CWE-269'));
const selected = store['整理漏洞與 Gemini 輸入'].selectedIds;
const responseData = {
  executiveSummaryZh: '今天有需要確認的安全情報。',
  analyses: selected.map(id => ({
    id, summaryZh: '官方資料顯示有一項漏洞公告。',
    relevance: '無法判定', priority: 'P2', reasonZh: '尚無資產版本清單。',
    actionZh: '請比對實際版本與官方公告。',
    product: 'SQL Server', isCompanyProduct: true, fixVersionZh: null, fixQuoteEn: null, fixQuoteZh: null, kevActionZh: null
  })),
  cweGuides: store['整理漏洞與 Gemini 輸入'].cweGuideTargets.map(cwe => ({ cwe, nameZh: '權限管理不當', riskZh: '可能被提升權限。', handlingZh: '更新並檢查權限設計。' }))
};
const aiResponse = {candidates:[{finishReason:'STOP',content:{parts:[{text:JSON.stringify(responseData)}]}}]};
const out = run('03-report.js',[aiResponse]);
assert(out.markdown.includes('CWE-269'));
assert(out.markdown.includes('NVD'));
const parsed=JSON.parse(out.jsonText);
assert(parsed.stats.analyzedCount > 0);
assert(parsed.records.every(x=>x.cwes.length>0));
const nodes=new Set(workflow.nodes.map(x=>x.name));
assert(nodes.size===workflow.nodes.length);
for(const [parent,conns] of Object.entries(workflow.connections)) {
  assert(nodes.has(parent));
  for(const line of conns.main||[]) for(const e of line) assert(nodes.has(e.node));
}
// 首頁應有 100 筆卻只回 2 筆，仍須停止發布。
store['取得 NVD 30h CVE'].totalResults=101;
assert.throws(()=>run('02-normalize.js'),/NVD/);
require('./regression-test.js');
require('./tools-test.js');
require('./public-config-test.js');
console.log('PASS: mock pipeline, schema, connected nodes, KEV flags, CWE-only, incomplete NVD guard.');
