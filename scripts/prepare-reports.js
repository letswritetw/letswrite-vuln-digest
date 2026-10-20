// 先建立今年至三年後的月份目錄；重跑不搬移、不刪除既有報告。
const fs = require('node:fs');
const path = require('node:path');

function prepareReportDirs(root, startYear) {
  for (let year = startYear; year < startYear + 4; year++) {
    for (let month = 1; month <= 12; month++) {
      fs.mkdirSync(path.join(root, String(year), String(month).padStart(2, '0')), { recursive: true });
    }
  }
}

if (require.main === module) {
  const root = path.resolve(process.argv[2] ?? path.join(__dirname, '..', 'reports'));
  const year = Number(new Intl.DateTimeFormat('en', { timeZone: 'Asia/Taipei', year: 'numeric' }).format(new Date()));
  prepareReportDirs(root, year);
  console.log(`${root}: ${year}-01 ~ ${year + 3}-12`);
}

module.exports = { prepareReportDirs };
