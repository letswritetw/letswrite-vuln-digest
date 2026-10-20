// 每個關注技術詞只取首頁，打包後才進入下一詞。
const query = $('建立時間區間').all(0, 0)[$runIndex]?.json;
const pages = $input.all().map(item => item.json);
if (!query?.nvdKeyword || !pages.length) throw new Error('關注查詢對應或 NVD 回應缺漏，停止發布；請完整執行工作流');
return [{ json: { keyword: query.nvdKeyword, pages } }];
