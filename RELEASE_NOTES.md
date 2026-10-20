# v1.0.0 — 資安戰情室首次發布

把關注的公開技術與 npm 套件公告，整理成繁體中文日報，透過唯讀儀表板查閱與追蹤。

原文依據：[README](README.md)「把關注的公開技術與 npm 套件公告，整理成每天一份的繁體中文日報。」

## 本版功能

- **情報蒐集與解讀**：n8n 串接 NVD、CISA KEV 與 GitHub Advisory，Gemini 協助解讀，輸出每日 JSON、Markdown 與 `latest.json`。原文依據：[README 資料流程](README.md#資料如何流動)「Gemini：協助解讀公告，程式驗證輸出」。
- **唯讀儀表板**：提供今天要做的事、CVE／CWE／產品篩選、歷史日報及 JSON／Markdown 下載，手動重新整理資料。原文依據：[儀表板說明](dashboard/README.md#查閱日報)「依 CVE、CWE、產品或查核優先級篩選，查看例行更新與其他情報。」及「切換歷史日期，閱讀或下載 JSON／Markdown。」
- **安裝與通知設定**：提供 Docker Compose、公開範例設定與 n8n Credential 匯入工具；Telegram 通知預設停用，可依需求開啟。原文依據：[README 安裝說明](README.md#安裝與第一次使用)「n8n 容器啟動時會依 config.json 產生工作流」；[通知說明](README.md#4選用telegram-通知)「預設不發通知，不設定 Telegram 也能產生日報。」
- **資料存取保護**：儀表板 API 限制請求方法、日期、路徑與符號連結，Markdown 經消毒後預覽。原文依據：[儀表板說明](dashboard/README.md#開發與檢查)「API 只接受 GET／HEAD」及「前端消毒 Markdown 後預覽，並限制日期、路徑與符號連結」。

## 開始使用

1. 將 `.env.example` 複製成 `.env`，填入 `GEMINI_API_KEY`。
2. 執行 `docker compose up -d --build`。
3. 開啟 `http://localhost:5678`，完成 n8n 設定並手動執行工作流。
4. 開啟 `http://localhost:3030`，重新整理並確認日報。
5. 手動產報成功後，再於 n8n 按 **Publish** 啟用排程。

原文依據：[README 第一次使用](README.md#安裝與第一次使用)「手動執行一次」及「按『重新整理』確認資料，再按 **Publish** 啟用工作流」。

## 本次驗證

| 指令 | 結果與輸出摘句 |
| --- | --- |
| `node build.js` | 成功；「節點：23」 |
| `node tests/smoke-test.js` | 60 項通過；「# pass 60」「# fail 0」 |
| `cd dashboard && npm test` | 11 項通過；「# pass 11」「# fail 0」 |
| `cd dashboard && npm run typecheck` | 成功；`vue-tsc --noEmit` 結束碼 0 |
| `cd dashboard && npm run build` | 成功；「1960 modules transformed.」「built in 1.07s」 |

以上摘句來自本次本機執行輸出。瀏覽器流程、Docker、真實來源 API、Gemini、Telegram、排程及跨作業系統整合未於本次實測；可用性證據來源未涵蓋。[README](README.md#開發與檢查) 原文：「離線測試使用假資料」。

## 使用限制

- **查核順序不代表已受影響**。原文依據：[README](README.md#日常怎麼使用)「『必做』與 P0～P3 都是查核順序，不代表已確認受影響。」
- **情報涵蓋有限**：NVD 查近 30 小時首次公布且有有效 CWE 的 CVE，每詞最多取得 100 筆、保留 10 筆；GitHub Advisory 依設定套件查詢；Gemini 每次最多分析 35 筆。原文依據：[範圍與限制](README.md#範圍與限制)「不會自動讀取專案或涵蓋完整相依樹」及「其他資料仍可能保留為未分析」。
- **仍有待補功能**。原文依據：[範圍與限制](README.md#範圍與限制)「檔案發布尚未原子化，完整失敗通知、可靠歷史補跑與自動修補尚未提供。」
- **網站免登入，預設只開放本機**。原文依據：[範圍與限制](README.md#範圍與限制)「提供其他裝置或外網使用前，請自行設置網路限制與身分驗證。」
