const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');
const base = path.resolve(__dirname, '..');
const expectedWorkflow = JSON.parse(fs.readFileSync(path.join(base, 'workflow/security-intel-gemini.json'), 'utf8'));

function withTempDir(run) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'cwe-node-tools-test-'));
  try { run(directory); }
  finally {
    assert(path.resolve(directory).startsWith(path.resolve(os.tmpdir()) + path.sep));
    fs.rmSync(directory, { recursive: true });
  }
}

test('Node 建置器輸出與既有工作流完全一致，重建不改變節點 ID', () => {
  const { createWorkflow } = require('../build.js');
  assert.deepEqual(createWorkflow(), expectedWorkflow);
  assert.deepEqual(createWorkflow(), createWorkflow());
});
test('空目錄會建立今年至三年後的 48 個月份目錄，支援中文路徑', () => {
  const { prepareReportDirs } = require('../scripts/prepare-reports.js');
  withTempDir(directory => {
    const root = path.join(directory, '文件', 'reports');
    prepareReportDirs(root, 2026);
    assert(fs.statSync(path.join(root, '2026', '01')).isDirectory());
    assert(fs.statSync(path.join(root, '2029', '12')).isDirectory());
    assert.equal(fs.readdirSync(root).reduce((count, year) => count + fs.readdirSync(path.join(root, year)).length, 0), 48);
  });
});
test('目錄工具重跑與延伸年份，保留新舊路徑的報告', () => {
  const { prepareReportDirs } = require('../scripts/prepare-reports.js');
  withTempDir(root => {
    const old = path.join(root, 'security-daily-2026-10-15.json');
    fs.writeFileSync(old, 'old');
    prepareReportDirs(root, 2026);
    const report = path.join(root, '2026', '10', 'security-daily-2026-10-16.json');
    fs.writeFileSync(report, 'report');
    prepareReportDirs(root, 2026);
    prepareReportDirs(root, 2027);
    assert.equal(fs.readFileSync(old, 'utf8'), 'old');
    assert.equal(fs.readFileSync(report, 'utf8'), 'report');
    assert(fs.statSync(path.join(root, '2030', '12')).isDirectory());
  });
});
test('檔案阻擋月份目錄時明確失敗，不覆寫既有檔案', () => {
  const { prepareReportDirs } = require('../scripts/prepare-reports.js');
  withTempDir(root => {
    const obstruction = path.join(root, '2026');
    fs.writeFileSync(obstruction, 'keep');
    assert.throws(() => prepareReportDirs(root, 2026), error => ['ENOTDIR', 'EEXIST'].includes(error.code));
    assert.equal(fs.readFileSync(obstruction, 'utf8'), 'keep');
  });
});
test('Node 目錄指令可從其他工作目錄執行，使用指定報告路徑', () => {
  withTempDir(directory => {
    const root = path.join(directory, '文件', 'reports');
    const result = spawnSync(process.execPath, [path.join(base, 'scripts/prepare-reports.js'), root], {
      cwd: directory, encoding: 'utf8',
    });
    assert.equal(result.status, 0, result.stderr);
    const year = Number(new Intl.DateTimeFormat('en', { timeZone: 'Asia/Taipei', year: 'numeric' }).format(new Date()));
    assert(fs.statSync(path.join(root, String(year), '01')).isDirectory());
    assert(fs.statSync(path.join(root, String(year + 3), '12')).isDirectory());
  });
});
test('容器匯入：.env 金鑰只進 Credential，工作流引用固定 ID，匯出檔不含金鑰', () => {
  const { setupFiles } = require('../scripts/n8n-setup.js');
  const env = { GEMINI_API_KEY: 'AIzaTestKey_1234567890', TELEGRAM_BOT_TOKEN: '123456:ABCdefGHIjklMNOpqrSTUvwx' };
  const { workflow, credentials } = setupFiles(env);
  assert.equal(workflow.id, expectedWorkflow.id);
  assert.deepEqual(credentials.map(c => c.type), ['httpHeaderAuth', 'telegramApi']);
  assert.equal(credentials[0].data.value, env.GEMINI_API_KEY);
  const node = name => workflow.nodes.find(n => n.name === name);
  assert.equal(node('Gemini 資安分析').credentials.httpHeaderAuth.id, credentials[0].id);
  assert.equal(node('發送 Telegram 通知').credentials.telegramApi.id, credentials[1].id);
  assert(!JSON.stringify(workflow).includes(env.GEMINI_API_KEY));
  assert(!JSON.stringify(expectedWorkflow).includes('credentials'));
  assert.deepEqual(setupFiles({}).credentials, []);
  assert.throws(() => setupFiles({ GEMINI_API_KEY: 'bad key\n' }), /GEMINI_API_KEY/);
});
