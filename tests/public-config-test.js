const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createWorkflow, scriptSource, validateConfig } = require('../build.js');

test('公開版預設使用可選的 Telegram Credential，所有外部來源驗證 TLS', () => {
  const workflow = createWorkflow();
  const notification = workflow.nodes.find(n => n.type === 'n8n-nodes-base.telegram');
  assert(notification, '工作流必須使用 Telegram 原生節點');
  assert.equal(notification.disabled, !require('../config.json').telegramEnabled);
  assert.equal(notification.typeVersion, 1.2);
  assert.equal(notification.parameters.operation, 'sendMessage');
  assert.equal(notification.parameters.additionalFields.parse_mode, 'HTML');
  assert.equal(notification.parameters.additionalFields.appendAttribution, false);
  const sample = 'foo_bar <b> & https://example.org/?a=1&b=2';
  const rendered = new Function('$', `return (${notification.parameters.text.slice(3, -2)});`)
    (() => ({ first: () => ({ json: { chatText: sample } }) }));
  assert.equal(rendered, 'foo_bar &lt;b&gt; &amp; https://example.org/?a=1&amp;b=2');
  assert(!notification.credentials, '匯出檔不能帶入個人 Credential');
  assert.equal(workflow.connections['寫入 latest.json'].main[0][0].node, notification.name);
  for (const node of workflow.nodes.filter(n => n.type.endsWith('.httpRequest'))) {
    assert(!node.parameters.options.allowUnauthorizedCerts, node.name);
  }
  assert(!JSON.stringify(workflow).includes('SYNO.Chat'));
});

test('自訂清單、模型與通知設定進入匯出檔，不依賴主機作業系統', () => {
  const config = { ...require('../config.json'),
    keywords: [{ keyword: 'macos', audience: ['全員電腦'], routine: true, vendorManaged: false, aliases: ['mac os'] }],
    npmPackages: ['vue'], model: 'gemini-example', dashboardUrl: 'https://security.example.org',
    telegramEnabled: true, telegramChatId: '-1001234567890' };
  const workflow = createWorkflow(config);
  const window = new Function(scriptSource('01-window.js', config))()[0].json;
  assert.deepEqual(window.companyKeywords, ['macos']);
  assert.deepEqual(window.npmPackages, ['vue']);
  assert.equal(workflow.nodes.find(n => n.name === 'Gemini 資安分析').parameters.url,
    'https://generativelanguage.googleapis.com/v1beta/models/gemini-example:generateContent');
  const notification = workflow.nodes.find(n => n.type.endsWith('.telegram'));
  assert.equal(notification.disabled, false);
  assert.equal(notification.parameters.chatId, config.telegramChatId);
});

test('空設定與損毀的設定在建置前失敗，避免發出無範圍查詢或無收件者通知', () => {
  assert.equal(typeof validateConfig, 'function');
  const good = require('../config.json');
  for (const patch of [
    { keywords: [] }, { keywords: [{ keyword: '', audience: [] }] },
    { keywords: [good.keywords[0], good.keywords[0]] },
    { npmPackages: [] }, { npmPackages: ['private package'] },
    { dashboardUrl: 'javascript:alert(1)' }, { model: '../invalid' },
    { telegramEnabled: true, telegramChatId: '' }, { telegramChatId: '={{ malicious }}' },
    { telegramBotToken: '不應出現在設定或匯出檔' },
  ]) assert.throws(() => validateConfig({ ...good, ...patch }), /設定/);
});
