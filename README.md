# 資安戰情室

把關注的公開技術與 npm 套件公告，整理成每天一份的繁體中文日報。n8n 負責蒐集與排程，Gemini 協助解讀，Vue 儀表板提供查閱；可選擇在產報後傳送 Telegram 通知。

像一份每天自動整理的技術剪報：先找到值得查核的公告，再由使用者確認自己是否使用受影響版本。它不會掃描你的電腦、自動修補或判定資產已受影響。

完整介紹見 [技術 Blog 文章]()。

## 資料如何流動

```text
NVD / CISA KEV / GitHub Advisory
               ↓
n8n：依設定清單蒐集、篩選與去除重複
               ↓
Gemini：協助解讀公告，程式驗證輸出
               ↓
每日 JSON + Markdown + latest.json
               ↓
Vue 唯讀儀表板 / Telegram 通知（選用）
```

官方資料是事實來源，AI 內容一律視為未經人工確認的說明。CVE 是漏洞編號，CWE 是弱點類型，CISA KEV 是已知被利用的漏洞清單。

## 支援平台與準備項目

macOS、Windows、Linux 都能使用。需要 Docker 與 Docker Compose（macOS 與 Windows 可使用 Docker Desktop），以及可使用所選模型的 Gemini API Key。一般使用不需要另外安裝 Node.js；只有開發、執行離線檢查或手動匯入工作流時才需要 Node.js 22.12 以上。

`scripts/01-window.js` 的 **window 指時間區間**，不是 Windows 作業系統；這支檔案計算查詢期間與報告日期。

## 安裝與第一次使用

### 1. 填入金鑰並啟動

將原始碼解壓縮後，在專案根目錄開啟終端機：

```bash
cp .env.example .env      # Windows PowerShell：Copy-Item .env.example .env
```

編輯 `.env`，在 `GEMINI_API_KEY=` 後面填入自己的 Gemini API Key，然後啟動：

```bash
docker compose up -d --build
```

n8n 容器啟動時會依 `config.json` 產生工作流，連同 `.env` 的金鑰自動匯入 n8n，並把 Gemini 節點接上 Credential，不需要手動匯入或選用。

| 服務   | 瀏覽器網址              |
| ------ | ----------------------- |
| n8n    | `http://localhost:5678` |
| 儀表板 | `http://localhost:3030` |

### 2. 手動產報，再啟用排程

開啟 n8n，依畫面完成首次帳號設定，打開「資安戰情室」工作流，手動執行一次。確認來源與 AI 驗證成功，並出現：

```text
reports/
├── latest.json
└── YYYY/MM/
    ├── security-daily-YYYY-MM-DD.json
    └── security-daily-YYYY-MM-DD.md
```

三份檔案的日期與內容應一致。若沒有符合分析條件的情報，工作流會跳過 Gemini，產生零筆日報；API 失敗不會當成零筆。

開啟儀表板、按「重新整理」確認資料，再按 **Publish** 啟用工作流。預設每天 `Asia/Taipei` 時區早上 07:00 執行；電腦與 Docker 必須保持運作。

### 3.（選用）調整關注清單

編輯 `config.json`：

| 設定              | 用途                                                                                |
| ----------------- | ----------------------------------------------------------------------------------- |
| `keywords`        | NVD 查詢清單；每項包含 `keyword`、`audience`、`routine`、`vendorManaged`、`aliases` |
| `npmPackages`     | GitHub Advisory 查詢的公開 npm 套件名稱                                             |
| `model`           | Gemini 模型名稱，預設 `gemini-3.5-flash-lite`                                       |
| `dashboardUrl`    | 通知附帶的儀表板網址，預設 `http://localhost:3030`                                  |
| `telegramEnabled` | 是否傳送 Telegram 通知，預設 `false`                                                |
| `telegramChatId`  | 接收通知的私人對話或群組 ID，預設空字串                                             |

`audience` 是建議由誰查核；`routine` 用於例行更新分類；`vendorManaged` 標示由服務供應者維護；`aliases` 提供同一技術的其他名稱。`keyword` 使用小寫。`audience` 可填「全員電腦」、「伺服器管理者」、「開發者」。至少需一個關鍵字與一個公開 npm 套件；空清單、重複項目或無效設定會讓 n8n 容器啟動失敗，可用 `docker compose logs n8n` 查看原因。

改完後執行：

```bash
docker compose up -d --force-recreate n8n
```

之後只要改了 `config.json` 或 `.env`，都執行這行指令。n8n 會重新匯入工作流；原本已啟用的排程會維持啟用。設定與金鑰沒有變更時，重新啟動會略過匯入。工作流以 `config.json` 為準，在 n8n 畫面直接修改的節點會在下次重新匯入時被覆蓋。

關鍵字與套件名稱會送往外部來源，公告也會送往 Gemini。只放允許對外查詢的公開名稱；API Key 與 Telegram Bot Token 只放在 `.env`，不要寫進 `config.json`。

### 4.（選用）Telegram 通知

預設不發通知，不設定 Telegram 也能產生日報。

1. 向 Telegram 的 `@BotFather` 建立 Bot，取得 Bot Token，填入 `.env` 的 `TELEGRAM_BOT_TOKEN`。
2. 私人對話先對 Bot 傳送 `/start`；群組通知則把 Bot 加入群組，確認具有發言權限。
3. 取得接收對話的 Chat ID，填入 `config.json` 的 `telegramChatId`，把 `telegramEnabled` 改為 `true`。
4. 執行 `docker compose up -d --force-recreate n8n`，Telegram 節點會自動接上 Credential。

可透過 Telegram Bot API 的 `getUpdates` 查詢自己 Bot 收到的訊息並取得 Chat ID。Bot API 請求網址含 Token，請勿公開完整網址、終端機紀錄或截圖。參考 [Telegram 官方 Bot 教學](https://core.telegram.org/bots/tutorial) 與 [getUpdates 文件](https://core.telegram.org/bots/api#getupdates)。

`localhost` 只代表目前裝置。若在手機開啟通知裡的儀表板連結，需把 `dashboardUrl` 改成手機可存取、且有適當存取控制的網址。改通知網址不會自動開放網站的網路綁定。Telegram 在檔案寫完後才發送；若只在通知節點失敗，請另外確認日報是否已經產生。

公開分享專案前，請把 `config.json` 還原為範例、清空 `telegramChatId` 並停用通知；不要分享 `.env` 或已填入個人設定的檔案。

### 金鑰與資料存放

- `.env` 以明文存在本機，已列入 `.gitignore`。n8n 啟動時會把金鑰加密存入 n8n Credentials，並在啟動 n8n 前移除金鑰環境變數；有主機 Docker 權限的人仍可用 `docker inspect` 看到容器設定的值。
- 報告以 `./reports:/files/reports` 掛載給 n8n；儀表板唯讀掛載同一份資料。Compose 的 `reports-init` 會建立報告年月目錄，並把專案 `reports/` 的擁有者調整為容器使用的 UID/GID 1000；請使用專案專屬的報告資料夾。
- n8n 設定與 Credentials 存在 Docker named volume，請一併備份。不要用 `docker compose down -v` 當成一般停止指令，以免刪除 n8n 資料卷。
- 在 macOS／Windows 的 Docker Desktop，請允許專案資料夾的檔案分享。`/files/reports` 是容器路徑，不需要在 Mac 或 Windows 根目錄另建 `/files`。若出現權限錯誤，先檢查初始化服務與掛載，不要直接開放所有人寫入。

### 已有 n8n 的使用者

參考 `n8n-compose-snippet.yml` 合併掛載與檔案存取設定，修改 `config.json` 後執行 `node build.js`，再到 n8n 選擇 **Import from File** 匯入 `workflow/security-intel-gemini.json`。在 Gemini 分析節點建立 **Header Auth Credential**（Header Name 填 `x-goog-api-key`，Header Value 填 API Key）；使用 Telegram 時在通知節點選用 **Telegram API Credential**。網站依 [dashboard/README.md](dashboard/README.md) 單獨啟動。

## 日常怎麼使用

1. 先確認日報日期與最後成功時間。
2. 看「今天要做的事」，查核自己是否使用受影響版本。
3. 點回官方來源，確認版本、條件與修補方式。
4. 需要時搜尋 CVE、CWE、產品，查看歷史或下載日報。

「必做」與 P0～P3 都是查核順序，不代表已確認受影響。網站只讀取報告、手動重新整理，不會再次呼叫 Gemini。新日報不需要重建容器；修改儀表板程式才需要重新建置。

## 範圍與限制

- NVD 只查最近 30 小時首次公布、符合關鍵字且具有有效 CWE 的 CVE；每詞最多取得 100 筆、依重要性保留 10 筆。描述沒提到技術名稱、太晚補上 CWE 或超過上限的資料，可能漏收。
- GitHub Advisory 依設定的 npm 套件查詢，不會自動讀取專案或涵蓋完整相依樹。CISA KEV 用於標記保留的 CVE，不會補入所有歷史漏洞。
- Gemini 每次最多分析 35 筆；其他資料仍可能保留為未分析。來源失敗或 AI 回覆驗證失敗會停止正常產報。
- 檔案發布尚未原子化，完整失敗通知、可靠歷史補跑與自動修補尚未提供。網站能顯示最後成功時間，不能判定 n8n 正在執行或失敗原因。
- 儀表板免登入且預設只綁定本機。提供其他裝置或外網使用前，請自行設置網路限制與身分驗證。備份報告與 n8n 資料卷；不要將真實報告、執行資料、Credentials 或私人設定上傳公開儲存庫。

## 開發與檢查

工作流修改後：

```bash
node build.js
node tests/smoke-test.js
```

儀表板修改後：

```bash
cd dashboard
npm ci
npm test
npm run typecheck
npm run build
```

離線測試使用假資料；不代表 Gemini／Telegram 金鑰、真實來源 API、Docker 掛載、macOS 或排程整合已驗證。儀表板的獨立啟動與開發說明見 [dashboard/README.md](dashboard/README.md)。
