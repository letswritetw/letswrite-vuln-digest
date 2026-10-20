import { test, expect, type Page } from '@playwright/test';

async function pick(page: Page, label: string, option: string) {
  await page.getByRole('combobox', { name: label }).click();
  await page.getByRole('option', { name: option, exact: true }).click();
}

test('必做卡片依序呈現，展開後顯示修補版本、原文摘句與 CWE 說明', async ({ page }) => {
  const errors: string[] = []; page.on('pageerror', error => errors.push(error.message));
  await page.goto('/');
  const cards = page.locator('.must-do-card');
  await expect(cards).toHaveCount(3);
  await expect(page.getByRole('heading', { name: /今天要做的事/ })).toBeVisible();
  await expect(page.getByText('部分蒐集', { exact: false })).toHaveCount(0);
  const kev = cards.filter({ hasText: '處理 Windows 已知被利用漏洞' });
  await expect(kev).toContainText('請見廠商公告');
  await kev.getByRole('button', { name: /處理 Windows/ }).click();
  await expect(kev.getByText('依廠商指示套用緩解措施。')).toBeVisible();
  await expect(kev.getByText('列入 KEV：2026-10-15')).toBeVisible();
  await expect(kev.getByRole('link', { name: /廠商公告/ })).toHaveAttribute('href', 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-10006');
  const axios = cards.nth(0);
  await expect(axios.locator('.card-title')).toHaveText('axios 出現惡意版本');
  const git = cards.filter({ hasText: '更新 Git' });
  await expect(git).toContainText('2.47.1 以上');
  const toggle = git.getByRole('button', { name: /更新 Git/ });
  await expect(toggle).toHaveAttribute('aria-expanded', 'false');
  await expect(git.getByText('Fixed in 2.47.1.', { exact: false })).toBeHidden();
  await toggle.click();
  await expect(toggle).toHaveAttribute('aria-expanded', 'true');
  await expect(git.getByText('Fixed in 2.47.1.', { exact: false })).toBeVisible();
  await expect(git.getByText('中譯：已於 2.47.1 版修正。')).toBeVisible();
  await expect(git.getByText('攻擊者可讓程式執行任意系統指令。')).toBeVisible();
  await expect(git.getByText('AI 說明，未經人工確認')).toBeVisible();
  await expect(git.getByText('AI 判定為關注清單中的產品', { exact: false })).toBeVisible();
  await expect(git.getByRole('link', { name: /CWE-78/ })).toHaveAttribute('href', 'https://cwe.mitre.org/data/definitions/78.html');
  await axios.getByRole('button', { name: /axios 出現惡意版本/ }).click();
  await expect(axios.getByText('檢查各專案 lockfile 是否裝到受影響版本', { exact: false })).toBeVisible();
  await expect(axios.getByText('= 1.14.1')).toBeVisible();
  await expect(axios.getByText('AI 未提供說明', { exact: false })).toBeVisible();
  const routine = page.getByRole('button', { name: /例行更新涵蓋 1 則/ });
  await expect(routine).toBeVisible();
  await routine.click();
  await expect(page.getByText('若為第三方軟體請另行確認', { exact: false })).toBeVisible();
  expect(errors).toEqual([]);
});

test('知悉即可預設收合，展開後可搜尋、篩選、看詳情與下載', async ({ page }) => {
  const errors: string[] = []; page.on('pageerror', error => errors.push(error.message));
  await page.goto('/');
  const fyi = page.getByRole('button', { name: /知悉即可（2 則）/ });
  await expect(fyi).toHaveAttribute('aria-expanded', 'false');
  await fyi.click();
  await expect(fyi).toHaveAttribute('aria-expanded', 'true');
  await expect(page.locator('.intel-row')).toHaveCount(2);
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 900 });
    const table = page.locator('.intel-table');
    expect(await table.evaluate(el => el.scrollWidth <= el.clientWidth), `width ${width}`).toBeTruthy();
  }
  await page.setViewportSize({ width: 1280, height: 900 });
  await pick(page, '分類', '全部');
  await expect(page.locator('.intel-row')).toHaveCount(7);
  await page.getByLabel('搜尋情報').fill('CWE-78');
  await expect(page.locator('.intel-row')).toHaveCount(2);
  await page.getByRole('button', { name: '清除篩選', exact: true }).click();
  await expect(page.locator('.intel-row')).toHaveCount(2);
  await page.locator('.intel-row').filter({ hasText: 'CVE-2026-10002' }).click();
  await expect(page.getByRole('heading', { name: 'CVE-2026-10002', exact: true })).toBeFocused();
  await expect(page.locator('.detail-panel a[href^="javascript:"]')).toHaveCount(0);
  const downloadEvent = page.waitForEvent('download');
  await page.getByRole('link', { name: 'JSON', exact: true }).click();
  expect((await downloadEvent).suggestedFilename()).toMatch(/^security-daily-\d{4}-\d{2}-\d{2}\.json$/);
  expect(errors).toEqual([]);
});

test('舊版日報與零必做日報的提示不同', async ({ page }) => {
  await page.goto('/'); await expect(page.locator('.must-do-card')).toHaveCount(3);
  await pick(page, '日報日期', '2026-01-01');
  await expect(page.getByText('今天沒有必做項目')).toBeVisible();
  await expect(page.getByText('沒有符合條件的更新，不代表使用環境沒有風險。')).toBeVisible();
  await expect(page.getByText('另有 1 筆可能必做的情報因 AI 分析上限未判定，列於知悉即可。')).toBeVisible();
  await expect(page.getByText('此日報產生於分類功能上線前', { exact: false })).toHaveCount(0);
  await pick(page, '日報日期', '2020-01-01');
  await expect(page.getByText('此日報產生於分類功能上線前', { exact: false })).toBeVisible();
  await expect(page.getByRole('heading', { name: /要做的事/ })).toHaveCount(0);
  await expect(page.getByText('本次沒有符合條件的情報')).toBeVisible();
});

test('歷史零筆與過期提示、刷新保留日期、Markdown 消毒', async ({ page }) => {
  await page.goto('/'); await expect(page.locator('.must-do-card')).toHaveCount(3);
  await page.getByRole('tab', { name: /日報閱讀/ }).click();
  await expect(page.locator('.markdown-body')).toContainText('可閱讀的官方摘要');
  await expect(page.locator('.markdown-body blockquote br')).toHaveCount(1);
  await expect(page.locator('.markdown-body script, .markdown-body img, .markdown-body [onerror], .markdown-body a[href^="javascript:"]')).toHaveCount(0);
  expect(await page.evaluate(() => (window as typeof window & { __xss?: number }).__xss)).toBeUndefined();
  await pick(page, '日報日期', '2020-01-01');
  await expect(page.getByText(/歷史資料：此報告距今超過 36 小時/)).toBeVisible();
  await page.getByRole('button', { name: '重新整理', exact: true }).click();
  await expect(page.getByRole('combobox', { name: '日報日期' })).toContainText('2020-01-01');
  await expect(page.locator('.markdown-body')).toContainText('測試日報');
  await page.getByRole('tab', { name: /情報總覽/ }).click();
  await expect(page.getByText('本次無 AI 分析')).toBeVisible();
  await expect(page.getByText('本次沒有符合條件的情報')).toBeVisible();
});

test('缺少日報、損毀與網路失敗不顯示零筆成功', async ({ page }) => {
  await page.route('**/api/reports/latest', route => route.fulfill({ status: 404, json: { error: 'missing' } }));
  await page.goto('/'); await expect(page.getByRole('heading', { name: '尚未收到日報' })).toBeVisible();
  await page.unroute('**/api/reports/latest');
  await page.route('**/api/reports/latest', route => route.fulfill({ status: 422, json: { error: 'corrupt' } }));
  await page.getByRole('button', { name: '檢查新報告' }).click();
  await expect(page.getByRole('alert')).toContainText('資料損毀');
  await expect(page.locator('.stats-strip')).toHaveCount(0);
  await page.unroute('**/api/reports/latest');
  await page.route('**/api/reports/latest', route => route.abort());
  await page.getByRole('button', { name: '重新整理', exact: true }).click();
  await expect(page.getByRole('alert')).toBeVisible();
});

test('1440／768／390／320 寬度下，必做卡片、知悉清單與詳情無橫向溢出', async ({ page }) => {
  for (const width of [1440, 768, 390, 320]) {
    await page.setViewportSize({ width, height: 960 });
    await page.goto('/'); await expect(page.locator('.must-do-card')).toHaveCount(3);
    await page.locator('.must-do-card').nth(1).getByRole('button').first().click();
    await page.getByRole('button', { name: /知悉即可/ }).click();
    await page.locator('.intel-row').first().click();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
    await page.screenshot({ path: `.verification/dashboard-${width}.png`, fullPage: true });
  }
});
