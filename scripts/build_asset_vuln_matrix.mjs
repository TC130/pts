import fs from "node:fs/promises";
import path from "node:path";
import { SpreadsheetFile, Workbook } from "@oai/artifact-tool";

const outputDir = path.resolve("outputs/asset_vuln_matrix");
const outputPath = path.join(outputDir, "资产-漏洞矩阵_20260527.xlsx");

const evidence = {
  example: "pentest_state/requests/example-com-baseline-20260527.txt",
  metropolitan: "pentest_state/requests/metropolitanpubcompany-baseline-20260527.txt",
  batch1: "pentest_state/requests/batch-27529-baseline-20260527.txt",
  batch2: "pentest_state/requests/batch2-27529-baseline-20260527.txt",
};

const assets = [
  {
    batch: "示例目标",
    url: "https://example.com/",
    tested: "已测试",
    connectivity: "已获得 HTTPS 响应",
    status: "HTTP 200，静态 Example Domain 页面",
    product: "Cloudflare / Example Domain",
    vulnIds: "EX-F001, EX-F002",
    vulnCount: 2,
    maxRisk: "中危",
    conclusion: "存在旧 TLS 协议支持和安全响应头缺失问题。",
    evidence: evidence.example,
    notes: "未执行业务操作；CORS 任意跨域未成立；证书未过期。",
  },
  {
    batch: "单目标",
    url: "https://www.metropolitanpubcompany.com/",
    tested: "已测试",
    connectivity: "HTTPS TLS 阶段被重置",
    status: "HTTPS 未进入应用层；HTTP 明文存在 403/307 边缘响应",
    product: "边缘/CDN 访问控制迹象",
    vulnIds: "",
    vulnCount: 0,
    maxRisk: "无",
    conclusion: "当前出口无法完成 HTTPS 应用层验证，未形成漏洞项。",
    evidence: evidence.metropolitan,
    notes: "记录为访问控制/边缘行为观察。",
  },
];

const batch1Targets = [
  "https://116.172.130.19:27529",
  "https://42.63.69.227:27529",
  "https://139.170.159.58:27529",
  "https://116.176.62.26:27529",
  "https://58.22.55.16:27529",
  "https://116.140.216.207:27529",
  "https://116.162.220.142:27529",
  "https://116.162.102.249:27529",
  "https://220.196.235.64:27529",
  "https://220.197.15.147:27529",
];

for (const url of batch1Targets) {
  assets.push({
    batch: "第一批 27529",
    url,
    tested: "已测试",
    connectivity: "连接超时",
    status: "未获得 HTTP 状态码/响应头/正文",
    product: "",
    vulnIds: "",
    vulnCount: 0,
    maxRisk: "无",
    conclusion: "当前代理出口无法有效验证应用层漏洞。",
    evidence: evidence.batch1,
    notes: "不能证明服务不存在，也不能证明不存在 Web 漏洞。",
  });
}

const batch2TimeoutTargets = [
  "https://180.130.121.141:27529",
  "https://124.89.83.10:27529",
  "https://125.39.72.95:27529",
  "https://121.29.88.46:27529",
  "https://211.90.218.102:27529",
  "https://58.242.188.204:27529",
  "https://58.144.197.46:27529",
  "https://153.0.237.15:27529",
  "https://182.90.229.118:27529",
  "https://58.250.244.186:27529",
  "https://124.88.80.6:27529",
  "https://123.126.40.155:27529",
  "https://61.156.89.193:27529",
  "https://218.60.118.108:27529",
  "https://125.41.24.247:27529",
  "https://221.204.39.53:27529",
];

for (const url of batch2TimeoutTargets) {
  assets.push({
    batch: "第二批 27529",
    url,
    tested: "已测试",
    connectivity: "连接超时",
    status: "未获得 HTTP 状态码/响应头/正文",
    product: "",
    vulnIds: "",
    vulnCount: 0,
    maxRisk: "无",
    conclusion: "当前代理出口无法有效验证应用层漏洞。",
    evidence: evidence.batch2,
    notes: "不能证明服务不存在，也不能证明不存在 Web 漏洞。",
  });
}

const batch2Accessible = [
  "https://116.169.59.80:27529",
  "https://116.147.35.178:27529",
  "https://116.182.22.103:27529",
  "https://106.74.127.23:27529",
];

for (const url of batch2Accessible) {
  assets.push({
    batch: "第二批 27529",
    url,
    tested: "已测试",
    connectivity: "已获得 HTTPS 响应",
    status: "根路径 302 到 /portal/；/portal/ 返回 200 OK",
    product: "Sangine / aTrust 2.0",
    vulnIds: "B2-F001, B2-F002",
    vulnCount: 2,
    maxRisk: "低危",
    conclusion: "存在安全响应头加固不足和未认证产品标识暴露。",
    evidence: evidence.batch2,
    notes: "CORS 任意跨域未成立；TLS 1.0/1.1 未成立。",
  });
}

const vulnerabilities = [
  {
    vulnId: "EX-F001",
    asset: "https://example.com/",
    title: "支持过时的 TLS 1.0 和 TLS 1.1 协议",
    risk: "中危",
    status: "已验证，存在漏洞",
    type: "TLS 配置弱项",
    claim: "限定 TLS 1.0 和 TLS 1.1 发起请求均可完成握手并返回 HTTP 200。",
    evidenceSummary: "TLSv1 / TLSv1.1 均返回 HTTP/1.1 200 OK；TLS 1.2 也可用。",
    evidence: evidence.example,
    remediation: "禁用 TLS 1.0/1.1，仅保留 TLS 1.2/1.3 和现代密码套件。",
  },
  {
    vulnId: "EX-F002",
    asset: "https://example.com/",
    title: "GET / 响应缺少多个 HTTP 安全响应头",
    risk: "低危",
    status: "已验证，存在漏洞",
    type: "HTTP 安全响应头加固不足",
    claim: "GET / 未返回 HSTS、CSP、X-Content-Type-Options、X-Frame-Options、Referrer-Policy、Permissions-Policy。",
    evidenceSummary: "GET / 返回 HTTP 200，但未观察到上述安全响应头。",
    evidence: evidence.example,
    remediation: "按业务兼容性补充 HSTS、CSP、X-Content-Type-Options、X-Frame-Options、Referrer-Policy、Permissions-Policy。",
  },
];

for (const url of batch2Accessible) {
  vulnerabilities.push(
    {
      vulnId: "B2-F001",
      asset: `${url}/portal/`,
      title: "可访问门户缺少 HSTS 和 Permissions-Policy 安全响应头",
      risk: "低危",
      status: "已验证，存在漏洞",
      type: "HTTP 安全响应头加固不足",
      claim: "/portal/ 返回 200 OK，已返回 CSP、X-Frame-Options、X-Content-Type-Options、Referrer-Policy，但未返回 HSTS 和 Permissions-Policy。",
      evidenceSummary: "4 个 Sangine 门户表现一致，响应头缺少 Strict-Transport-Security 和 Permissions-Policy。",
      evidence: evidence.batch2,
      remediation: "结合域名访问场景启用 HSTS，并补充 Permissions-Policy。",
    },
    {
      vulnId: "B2-F002",
      asset: url,
      title: "未认证响应暴露产品/平台标识",
      risk: "低危",
      status: "已验证，存在漏洞",
      type: "信息泄露 / 指纹信息暴露",
      claim: "未认证响应暴露 Server: Sangine；由前端 JS 派生的 /nap_information/ 404 页面标题暴露 aTrust 2.0。",
      evidenceSummary: "根路径响应 Server: Sangine；/nap_information/ 返回 404，title 为 aTrust 2.0。",
      evidence: evidence.batch2,
      remediation: "隐藏或泛化 Server 头，自定义错误页，减少前端配置中的产品指纹。",
    },
  );
}

const validations = [
  ["https://example.com/", "CORS 任意跨域", "已测试，当前证据不支持漏洞成立", "任意 Origin 请求未返回 Access-Control-Allow-Origin / Access-Control-Allow-Credentials", evidence.example],
  ["https://example.com/", "证书过期", "已测试，当前证据不支持漏洞成立", "观察到证书到期时间为 2026-07-01 GMT，测试时未过期", evidence.example],
  ["https://www.metropolitanpubcompany.com/", "CORS / 安全头 / TLS 配置", "未完成有效验证", "HTTPS 在 TLS ClientHello 后被重置，未进入 HTTP 应用层", evidence.metropolitan],
  ["第一批 10 个 :27529 目标", "CORS / 安全头 / TLS / 业务接口", "未完成有效验证", "全部连接超时，未获得 HTTP 响应", evidence.batch1],
  ["第二批 16 个超时 :27529 目标", "CORS / 安全头 / TLS / 业务接口", "未完成有效验证", "全部连接超时，未获得 HTTP 响应", evidence.batch2],
  ["第二批 4 个可访问 :27529 目标", "CORS 任意跨域", "已测试，当前证据不支持漏洞成立", "任意 Origin 请求未返回 Access-Control-Allow-Origin / Access-Control-Allow-Credentials", evidence.batch2],
  ["第二批 4 个可访问 :27529 目标", "支持 TLS 1.0 / TLS 1.1", "已测试，当前证据不支持漏洞成立", "TLS 1.0/1.1 返回 protocol version alert，TLS 1.2 可用", evidence.batch2],
];

const evidenceIndex = [
  [evidence.example, "example.com 只读基线测试", "含 TLS、安全头、CORS、证书观察"],
  [evidence.metropolitan, "metropolitanpubcompany.com 只读基线测试", "含 HTTPS 重置、HTTP 边缘响应观察"],
  [evidence.batch1, "第一批 10 个 27529 目标", "全部连接超时的判活证据"],
  [evidence.batch2, "第二批 20 个 27529 目标", "4 个可访问目标和 16 个超时目标的证据"],
];

const workbook = Workbook.create();
const summary = workbook.worksheets.add("总览");
const matrix = workbook.worksheets.add("资产矩阵");
const detail = workbook.worksheets.add("漏洞明细");
const negative = workbook.worksheets.add("未成立或未验证");
const evidenceSheet = workbook.worksheets.add("证据索引");

function writeTable(sheet, startCell, headers, rows, tableName) {
  const range = sheet.getRange(startCell).resize(rows.length + 1, headers.length);
  range.values = [headers, ...rows];
  const table = sheet.tables.add(range.address, true, tableName);
  table.style = "TableStyleMedium2";
  return range;
}

function styleSheet(sheet, usedRange, widths = []) {
  sheet.showGridLines = false;
  sheet.freezePanes.freezeRows(1);
  usedRange.format.font.name = "Arial";
  usedRange.format.font.size = 10;
  usedRange.format.wrapText = true;
  usedRange.format.verticalAlignment = "Top";
  usedRange.format.autofitRows();
  widths.forEach((w, idx) => {
    sheet.getRangeByIndexes(0, idx, 1, 1).getColumn(0).format.columnWidthPx = w;
  });
}

const totalAssets = assets.length;
const responded = assets.filter((a) => a.connectivity === "已获得 HTTPS 响应").length;
const timeoutOrBlocked = assets.filter((a) => a.connectivity !== "已获得 HTTPS 响应").length;
const vulnerableAssets = assets.filter((a) => a.vulnCount > 0).length;
const vulnInstances = vulnerabilities.length;
const mediumCount = vulnerabilities.filter((v) => v.risk === "中危").length;
const lowCount = vulnerabilities.filter((v) => v.risk === "低危").length;

summary.getRange("A1:H1").merge();
summary.getRange("A1").values = [["Web 资产-漏洞测试汇总"]];
summary.getRange("A1").format.font.bold = true;
summary.getRange("A1").format.font.size = 18;
summary.getRange("A1").format.fill.color = "#1F4E79";
summary.getRange("A1").format.font.color = "#FFFFFF";

summary.getRange("A3:B10").values = [
  ["测试日期", "2026-05-27"],
  ["代理出口", "39.106.140.81"],
  ["资产总数", totalAssets],
  ["获得 HTTPS 响应资产数", responded],
  ["超时/阻断/未进入 HTTPS 应用层资产数", timeoutOrBlocked],
  ["存在漏洞资产数", vulnerableAssets],
  ["漏洞实例数", vulnInstances],
  ["报告语言", "中文"],
];
summary.getRange("D3:E7").values = [
  ["风险等级", "数量"],
  ["中危", mediumCount],
  ["低危", lowCount],
  ["无漏洞结论/无法验证资产", totalAssets - vulnerableAssets],
  ["未执行状态变更请求", "是"],
];

summary.getRange("A12:H16").values = [
  ["说明"],
  ["1. “已验证，存在漏洞”只用于证据链支持的漏洞项。"],
  ["2. 连接超时或 TLS 阶段重置不等同于不存在漏洞，只表示当前代理出口路径无法有效验证。"],
  ["3. 本工作簿只汇总已执行的只读 Web 测试，未包含登录态、业务提交、短信或账号权限验证。"],
  ["4. 证据文件路径可在“证据索引”和各明细行中找到。"],
];
summary.getRange("A12:H12").merge();
summary.getRange("A13:H13").merge();
summary.getRange("A14:H14").merge();
summary.getRange("A15:H15").merge();
summary.getRange("A16:H16").merge();

const riskChartRange = summary.getRange("D3:E6");
const chart = summary.charts.add("bar", riskChartRange);
chart.setPosition("G3", "L14");
chart.title = "风险与状态分布";
chart.hasLegend = false;

styleSheet(summary, summary.getRange("A1:L16"), [150, 260, 30, 130, 140, 30, 120, 120]);

const assetRows = assets.map((a) => [
  a.batch,
  a.url,
  a.tested,
  a.connectivity,
  a.status,
  a.product,
  a.vulnCount,
  a.maxRisk,
  a.vulnIds,
  a.conclusion,
  a.evidence,
  a.notes,
]);
writeTable(
  matrix,
  "A1",
  ["批次", "资产", "测试状态", "连通性/响应", "HTTP 状态或行为", "识别产品", "漏洞数", "最高风险", "漏洞编号", "主要结论", "证据文件", "备注"],
  assetRows,
  "AssetMatrix",
);
styleSheet(matrix, matrix.getRange(`A1:L${assetRows.length + 1}`), [110, 260, 90, 150, 230, 130, 70, 80, 120, 280, 260, 280]);

const vulnRows = vulnerabilities.map((v) => [
  v.vulnId,
  v.asset,
  v.title,
  v.risk,
  v.status,
  v.type,
  v.claim,
  v.evidenceSummary,
  v.evidence,
  v.remediation,
]);
writeTable(
  detail,
  "A1",
  ["漏洞编号", "影响资产", "漏洞名称", "风险等级", "验证状态", "漏洞类型", "论点", "论据摘要", "证据文件", "修复建议"],
  vulnRows,
  "VulnerabilityDetails",
);
styleSheet(detail, detail.getRange(`A1:J${vulnRows.length + 1}`), [90, 260, 260, 80, 130, 150, 360, 360, 260, 360]);

writeTable(
  negative,
  "A1",
  ["资产或范围", "测试项", "验证状态", "说明", "证据文件"],
  validations,
  "ValidationMatrix",
);
styleSheet(negative, negative.getRange(`A1:E${validations.length + 1}`), [260, 180, 180, 420, 260]);

writeTable(evidenceSheet, "A1", ["证据文件", "对应测试", "内容说明"], evidenceIndex, "EvidenceIndex");
styleSheet(evidenceSheet, evidenceSheet.getRange(`A1:C${evidenceIndex.length + 1}`), [320, 250, 420]);

for (const sheet of [matrix, detail, negative, evidenceSheet]) {
  sheet.getRange("A1:Z1").format.font.bold = true;
  sheet.getRange("A1:Z1").format.fill.color = "#D9EAF7";
}

await fs.mkdir(outputDir, { recursive: true });

const inspectSummary = await workbook.inspect({
  kind: "table",
  range: "资产矩阵!A1:L8",
  include: "values",
  tableMaxRows: 8,
  tableMaxCols: 12,
  maxChars: 5000,
});
console.log(inspectSummary.ndjson);

const errors = await workbook.inspect({
  kind: "match",
  searchTerm: "#REF!|#DIV/0!|#VALUE!|#NAME\\?|#N/A",
  options: { useRegex: true, maxResults: 100 },
  summary: "formula error scan",
});
console.log(errors.ndjson);

for (const sheetName of ["总览", "资产矩阵", "漏洞明细", "未成立或未验证", "证据索引"]) {
  const preview = await workbook.render({ sheetName, autoCrop: "all", scale: 1, format: "png" });
  const bytes = new Uint8Array(await preview.arrayBuffer());
  await fs.writeFile(path.join(outputDir, `${sheetName}.png`), bytes);
}

const xlsx = await SpreadsheetFile.exportXlsx(workbook);
await xlsx.save(outputPath);
console.log(outputPath);
