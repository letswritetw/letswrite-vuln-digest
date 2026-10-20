# 儀表板視覺規範

全部使用 Balsa UI 原生元件與預設主題，不另外自訂配色或元件外觀。介面跟著使用者電腦的淺色／深色模式自動切換，顏色由 Balsa 的語意 token（`--balsa-role-*`）提供。

## 元件對應
| 區塊 | Balsa 元件 |
| --- | --- |
| 日報日期、分類與篩選 | `Select`、`Input`、`Checkbox` |
| 情報總覽／日報閱讀切換 | `Tabs`（segmented，面板不加外框，避免框中框） |
| 資料過期、舊版日報、錯誤等提示 | `Alert`（設為 persistent，重要說明不能被關掉） |
| 今天要做的事（必做卡片） | `Collapsible`（surface）＋ `Badge`、`Link` |
| 例行更新、知悉即可、資料範圍與限制 | `Collapsible` |
| 今日摘要、詳情、Markdown 日報 | `Card` |
| 情報統計 | `MetricGridCard` |
| 知悉清單 | `Table`（關閉 hover，用原生 `data-selected` 標示選取列；文字自動換行，不出現橫向捲軸） |
| 載入中 | `Skeleton` |
| 按鈕、下載與外部連結 | `Button`、`Link` |

元件以官方 CLI（`npx balsa-ui@latest add <名稱>`）安裝到 `src/components/ui/` 與 `src/components/compositions/`，不手動改元件原始碼。

## 版面
單欄、靠左，最大寬度 960px。由上往下：頂部日期與重新整理 → 日期、狀態與下載 → 提示 → 情報總覽／日報閱讀分頁（今天要做的事、例行更新、今日摘要、情報統計、知悉即可）→ 資料範圍與限制。舊版日報沒有分類欄位時，不顯示必做區，清單直接展開。

`src/style.css` 只負責排列、間距與 Markdown 排版（Markdown 以單一換行當作換行顯示，舊日報開頭的引用資訊也會逐行呈現）；需要顏色時只用 `--balsa-role-*`。不使用紅色警報燈號暗示使用者的資產已受影響；CVE 編號與版本號用等寬字體；字型不外連。
