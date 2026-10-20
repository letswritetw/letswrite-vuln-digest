# 公開版開發規範

這是 n8n + Gemini + Vue 的唯讀資安戰情室。文件、UI 與報告使用台灣繁體中文，既有技術名稱與 JSON 欄位保持原文。

## 修改原則

- 先讀 README 與直接相關原始碼，採最小完整修改，不新增不必要依賴。
- `config.json` 是公開範例設定；不得提交真實報告、私人技術清單、主機位址、Credentials、API Key 或 Bot Token。需要密鑰時使用 n8n Credentials。
- `scripts/01-window.js` 的 window 是時間區間，程式需保持 macOS／Windows／Linux 的 Node.js 相容性。
- 官方欄位是事實來源；AI 僅協助解讀。不得把技術名稱相符或情報優先級寫成已確認受影響。
- 保持 JSON schema 與歷史日報相容。儀表板唯讀、手動重新整理，不在前端取得情報或呼叫 Gemini。

## 工作流同步與驗證

`build.js` 將設定、腳本與節點接線寫入 `workflow/security-intel-gemini.json`。修改 `config.json`、工作流腳本或節點時，需同步建置與檢查：

```bash
node build.js
node tests/smoke-test.js
```

`scripts/n8n-setup.js` 在 n8n 容器啟動時匯入工作流與 `.env` 金鑰；工作流與 Credential 的固定 ID 不可任意更改，否則重新匯入會產生重複副本。匯出檔不得帶入 Credential。

修改 Code 節點名稱時，要同步更新 `$('節點名稱')` 引用與測試。確認目標 n8n 的節點版本相容性。禁止因略過錯誤而發布成功日報，來源故障也不得被視為零筆。

儀表板修改需在 `dashboard/` 執行：

```bash
npm test
npm run typecheck
npm run build
```

保留路徑限制、資料驗證與 Markdown 消毒。Balsa UI 沿用現有元件與預設主題，規範見 `dashboard/DESIGN.md`。

回報變更與已執行的測試。沒有實測的 Docker、作業系統、API、通知或排程，需明確列為未驗證。不得自行部署、推送、發通知或連線私人主機。
