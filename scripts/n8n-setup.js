// n8n 容器啟動前執行：依 config.json 與 .env 匯入工作流和 Credentials；內容未變更時略過。
// 匯入會取消啟用工作流，因此先記錄原本的啟用狀態，匯入後再發布回來。
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { createWorkflow } = require('../build.js');

const GEMINI = { id: 'cweGeminiApiKey1', name: 'Gemini API Key' };
const TELEGRAM = { id: 'cweTelegramBot01', name: 'Telegram Bot' };

function setupFiles(env, config) {
  const workflow = createWorkflow(config);
  const credentials = [];
  const node = name => workflow.nodes.find(n => n.name === name);
  const secret = (key, pattern) => {
    const value = (env[key] || '').trim();
    if (value && !pattern.test(value)) throw new Error(`.env 的 ${key} 格式無效，請重新複製。`);
    return value;
  };
  const gemini = secret('GEMINI_API_KEY', /^[A-Za-z0-9_-]{10,200}$/);
  const telegram = secret('TELEGRAM_BOT_TOKEN', /^\d{1,20}:[A-Za-z0-9_-]{20,100}$/);
  if (gemini) {
    credentials.push({ ...GEMINI, type: 'httpHeaderAuth', data: { name: 'x-goog-api-key', value: gemini } });
    node('Gemini 資安分析').credentials = { httpHeaderAuth: GEMINI };
  }
  if (telegram) {
    credentials.push({ ...TELEGRAM, type: 'telegramApi', data: { accessToken: telegram } });
    node('發送 Telegram 通知').credentials = { telegramApi: TELEGRAM };
  }
  return { workflow, credentials };
}

function main() {
  const { workflow, credentials } = setupFiles(process.env);
  if (!credentials.some(c => c.type === 'httpHeaderAuth')) console.warn('未設定 GEMINI_API_KEY：請在 .env 填入，或到 n8n 的 Gemini 節點手動選用 Credential。');
  const marker = path.join(os.homedir(), '.n8n', 'letswrite-setup.sha256');
  const hash = createHash('sha256').update(JSON.stringify({ workflow, credentials })).digest('hex');
  if (fs.existsSync(marker) && fs.readFileSync(marker, 'utf8') === hash) return console.log('工作流與 Credentials 未變更，略過匯入。');

  const n8n = (...args) => execFileSync('n8n', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'n8n-setup-'));
  try {
    const wasActive = n8n('list:workflow', '--active=true', '--onlyId').split(/\s+/).includes(workflow.id);
    if (credentials.length) {
      const file = path.join(dir, 'credentials.json');
      fs.writeFileSync(file, JSON.stringify(credentials), { mode: 0o600 });
      n8n('import:credentials', `--input=${file}`);
    }
    const file = path.join(dir, 'workflow.json');
    fs.writeFileSync(file, JSON.stringify(workflow));
    n8n('import:workflow', `--input=${file}`);
    if (wasActive) n8n('publish:workflow', `--id=${workflow.id}`);
    fs.writeFileSync(marker, hash);
    console.log(`已匯入工作流${credentials.length ? '與 Credentials' : ''}${wasActive ? '，並維持啟用' : '；確認手動執行成功後再啟用排程'}。`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

if (require.main === module) main();

module.exports = { setupFiles };
