// n8n Code node - Run Once for All Items
// window 指蒐集時間區間，不是 Windows；macOS、Windows、Linux 共用相同 Node.js 程式。
// PUBLIC_CONFIG 由 build.js 讀取 config.json 後嵌入，執行時不讀取主機檔案。
const companyKeywords = PUBLIC_CONFIG.keywords.map(p => p.keyword);
const keywordProfiles = Object.fromEntries(PUBLIC_CONFIG.keywords.map(({ keyword, ...profile }) => [keyword, profile]));
const npmPackages = PUBLIC_CONFIG.npmPackages;
const now = new Date();
const start = new Date(now.getTime() - 30 * 60 * 60 * 1000);
const dateTW = new Intl.DateTimeFormat('sv-SE', { timeZone: 'Asia/Taipei', year: 'numeric', month: '2-digit', day: '2-digit' }).format(now);
const window = {
  dateTW,
  fetchedAt: now.toISOString(),
  startUtc: start.toISOString(),
  endUtc: now.toISOString(),
  // NVD API supports extended ISO-8601 with a UTC offset.
  nvdStart: start.toISOString().replace('Z', '+00:00'),
  nvdEnd: now.toISOString().replace('Z', '+00:00'),
  // GitHub Advisory 的 published 只吃日期範圍；精確時間由整理節點再核對。
  ghsaPublished: `${start.toISOString().slice(0, 10)}..${now.toISOString().slice(0, 10)}`,
};
return companyKeywords.map(nvdKeyword => ({ json: {
  ...window, nvdKeyword, companyKeywords, keywordProfiles, npmPackages, ghsaAffects: npmPackages.join(','),
} }));
