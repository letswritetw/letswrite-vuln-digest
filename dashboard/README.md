# 資安儀表板

把 n8n 產生的 JSON 日報變成唯讀網站。Vue 3 + TypeScript + Vite，介面使用 Balsa UI；不會再次呼叫 Gemini，也不會修改報告。視覺規範見 [DESIGN.md](DESIGN.md)。

## 啟動

新使用者建議依照 [根目錄 README](../README.md)，在專案根目錄啟動 n8n 與儀表板。

若已有 n8n、只要啟動儀表板，可以從這個目錄執行：

```bash
docker compose up -d --build
```

瀏覽器開啟 **http://localhost:3030**。預設只監聽本機，不需要 `.env`；報告唯讀掛載自 `../reports`。不要同時啟動根目錄與這裡的儀表板服務，以免占用相同連接埠。

若報告在其他目錄，將 `.env.example` 複製為 `.env`，調整 `REPORTS_HOST_DIR`。Docker Desktop 需允許該路徑的檔案分享；Linux 需確保容器 UID 1000 可讀取報告與進入所有年月子目錄，不必讓所有人都能寫入。

網站免登入。若調整 `DASHBOARD_BIND` 讓其他裝置可連線，需一併規劃存取控制；請勿直接把報告網站開放至公開網路。

## 查閱日報

1. 確認日期與最後成功產報時間，再看「今天要做的事」。
2. 點開情報查看官方來源、修補版本摘句、CWE 與 AI 說明，查核自己使用的版本。
3. 依 CVE、CWE、產品或查核優先級篩選，查看例行更新與其他情報。
4. 切換歷史日期，閱讀或下載 JSON／Markdown。

AI 內容未經人工確認；P0～P3 表示情報查核順序，不代表已確認受影響。網站會區分尚無日報、零筆、未分析、資料過期與資料損毀。

n8n 寫入新日報後，按「重新整理」即可；資料更新不用重建容器。網站不自動輪詢，無法得知 n8n 是否正在執行或為何失敗。歷史 API 相容年月目錄與舊平面目錄，不搬移、不刪除既有報告。

## 開發與檢查

本機使用 Node.js 22.12 以上：

```bash
npm ci
npm test
npm run typecheck
npm run build
npm start
```

本機 Node 服務預設只監聽 `127.0.0.1:3030` 並讀取專案 `reports/`。其他報告位置可在 `.env` 設定 `REPORTS_DIR` 絕對路徑，再執行 `node --env-file=.env server.mjs`；`DASHBOARD_BIND` 僅控制 Docker 主機綁定。

瀏覽器流程與響應式尺寸檢查：

```bash
npx playwright install chromium
npm run test:browser
```

測試使用暫存假資料與本機 3031 服務；已有 Chromium 時，可透過 `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH` 指定。這些檢查不代表外部 API、真實報告、Docker 或不同作業系統已實測。

服務與日誌：

```bash
docker compose ps
docker compose logs --tail=50
```

API 只接受 GET／HEAD，提供驗證過的日報清單、JSON 與 Markdown，前端消毒 Markdown 後預覽，並限制日期、路徑與符號連結。報告目錄以 `:ro` 掛載，不包進 image，金鑰不進前端。
