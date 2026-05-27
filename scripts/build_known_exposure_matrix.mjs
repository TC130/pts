import fs from "node:fs/promises";
import path from "node:path";
import { SpreadsheetFile, Workbook } from "@oai/artifact-tool";

const resultsPath = process.env.PENTEST_RESULTS_JSONL || "outputs/known_exposure_20260527/known_exposure_results.jsonl";
const summaryPath = process.env.PENTEST_SUMMARY_JSON || "outputs/known_exposure_20260527/summary.json";
const outputDir = path.resolve(process.env.PENTEST_OUTPUT_DIR || "outputs/known_exposure_20260527");
const outputPath = path.join(outputDir, process.env.PENTEST_OUTPUT_XLSX || "已知暴露面资产漏洞矩阵_20260527.xlsx");
const reportPath = "pentest_state/report-known-exposure-checks-20260527.md";
const evidencePath = "pentest_state/requests/known-exposure-checks-20260527.txt";

const rows = (await fs.readFile(resultsPath, "utf8"))
  .trim()
  .split(/\n+/)
  .filter(Boolean)
  .map((line) => JSON.parse(line));
const summary = JSON.parse(await fs.readFile(summaryPath, "utf8"));

function cleanCell(value) {
  if (typeof value !== "string") return value;
  return value.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g, " ").slice(0, 32000);
}

function assetRisk(classifications) {
  if (classifications.includes("Actuator 暴露")) return "高危/中危";
  if (classifications.includes("API 文档暴露") || classifications.includes(".env 暴露") || classifications.includes("source map 暴露")) return "高危";
  return "无";
}

function verification(classification) {
  return classification === "Actuator 暴露" ? "已验证，存在漏洞" : "已测试，未发现该类暴露";
}

const byOrigin = new Map();
for (const row of rows) {
  if (!byOrigin.has(row.origin)) byOrigin.set(row.origin, []);
  byOrigin.get(row.origin).push(row);
}

const assetRows = [...byOrigin.entries()].map(([origin, items]) => {
  const counts = {};
  for (const item of items) counts[item.classification] = (counts[item.classification] || 0) + 1;
  const findings = items.filter((item) => item.classification === "Actuator 暴露");
  return [
    origin,
    items.length,
    counts["Actuator 暴露"] || 0,
    counts["未暴露"] || 0,
    counts["无法验证"] || 0,
    assetRisk(items.map((item) => item.classification)),
    findings.length ? findings.map((item) => item.url).join("\n") : "未发现明确漏洞项",
    findings.length ? "Actuator 管理端点未授权暴露" : "未发现 .env / Swagger / Actuator / source map 暴露",
    findings.length ? "已验证，存在漏洞" : "已测试，当前证据不支持漏洞成立",
    items.find((item) => item.server)?.server || "-",
    items.find((item) => item.status)?.status || "-",
  ];
});

const findingRows = rows
  .filter((row) => row.classification === "Actuator 暴露")
  .map((row) => [
    row.origin,
    row.url,
    row.origin === "https://fm-adx.wostore.cn/" ? "高危" : "中危",
    verification(row.classification),
    "Spring Boot Actuator 管理端点未授权暴露",
    row.status,
    row.content_type || "-",
    row.body_snippet || "-",
    reportPath,
  ]);

const falsePositiveRows = [
  ["220.196.214.104:20443 / cloudgamecm.wostore.cn:18010", "敏感路径返回“云联壹云”前端 HTML 壳", "已剔除，不作为 .env / Swagger / Actuator 暴露"],
  ["qyphone.wostore.cn:30443 / qyphone.wostore.cn:32001", "敏感路径返回前端应用壳，提示需要启用 JavaScript", "已剔除，不作为公开信息文件"],
  ["9cfx.cn / lo7.cn", "206 响应正文明确提示 URL 不存在或已过期", "已剔除，不作为暴露"],
  ["member.zlhz.wostore.cn / speedupload.wostore.cn", "source map 路径返回 text/html 页面而非 source map JSON", "已剔除，不作为 source map 暴露"],
];

const workbook = Workbook.create();
const shSummary = workbook.worksheets.add("总览");
const shAssets = workbook.worksheets.add("资产矩阵");
const shFindings = workbook.worksheets.add("已验证漏洞");
const shFalsePositive = workbook.worksheets.add("误报剔除");
const shEvidence = workbook.worksheets.add("证据索引");

function writeTable(sheet, start, headers, data, name) {
  const range = sheet.getRange(start).resize(data.length + 1, headers.length);
  range.values = [headers, ...data].map((row) => row.map(cleanCell));
  const table = sheet.tables.add(range.address, true, name);
  table.style = "TableStyleMedium2";
  return range;
}

function style(sheet, range, widths) {
  sheet.showGridLines = false;
  sheet.freezePanes.freezeRows(1);
  range.format.font.name = "Arial";
  range.format.font.size = 10;
  range.format.wrapText = true;
  range.format.verticalAlignment = "Top";
  widths.forEach((width, idx) => {
    sheet.getRangeByIndexes(0, idx, 1, 1).getColumn(0).format.columnWidthPx = width;
  });
  sheet.getRange("A1:Z1").format.font.bold = true;
  sheet.getRange("A1:Z1").format.fill.color = "#D9EAF7";
  range.format.autofitRows();
}

shSummary.getRange("A1:H1").merge();
shSummary.getRange("A1").values = [["已知暴露面低频检查汇总"]];
shSummary.getRange("A1").format.font.bold = true;
shSummary.getRange("A1").format.font.size = 18;
shSummary.getRange("A1").format.fill.color = "#1F4E79";
shSummary.getRange("A1").format.font.color = "#FFFFFF";
shSummary.getRange("A3:B10").values = [
  ["测试日期", "2026-05-27"],
  ["代理出口", "39.106.140.81"],
  ["Origin 数", summary.origins],
  ["请求数", summary.tests],
  ["已验证漏洞端点", summary.notable_count],
  ["公开信息文件", summary.public_info_count],
  ["误报处理", "已剔除 SPA/404/网关错误页"],
  ["证据报告", reportPath],
];
shSummary.getRange("D3:E7").values = [
  ["分类", "数量"],
  ["未暴露", summary.classification_counts["未暴露"] || 0],
  ["无法验证", summary.classification_counts["无法验证"] || 0],
  ["Actuator 暴露", summary.classification_counts["Actuator 暴露"] || 0],
  ["其他", summary.tests - (summary.classification_counts["未暴露"] || 0) - (summary.classification_counts["无法验证"] || 0) - (summary.classification_counts["Actuator 暴露"] || 0)],
];
style(shSummary, shSummary.getRange("A1:H12"), [150, 360, 40, 150, 110, 40, 110, 110]);

writeTable(shAssets, "A1", ["资产 Origin", "测试请求数", "Actuator 暴露端点数", "未暴露数", "无法验证数", "最高风险", "漏洞端点", "问题摘要", "验证状态", "Server 示例", "响应示例"], assetRows, "KnownExposureAssets");
style(shAssets, shAssets.getRange(`A1:K${assetRows.length + 1}`), [300, 90, 130, 90, 90, 90, 420, 300, 180, 160, 180]);

writeTable(shFindings, "A1", ["资产", "漏洞 URL", "风险等级", "验证状态", "漏洞名称", "响应状态", "Content-Type", "论据摘要", "报告文件"], findingRows, "KnownExposureFindings");
style(shFindings, shFindings.getRange(`A1:I${findingRows.length + 1}`), [260, 360, 80, 150, 260, 140, 140, 520, 320]);

writeTable(shFalsePositive, "A1", ["资产/范围", "误报原因", "处理结论"], falsePositiveRows, "KnownExposureFalsePositives");
style(shFalsePositive, shFalsePositive.getRange(`A1:C${falsePositiveRows.length + 1}`), [300, 440, 360]);

writeTable(shEvidence, "A1", ["证据/文件", "说明"], [
  [evidencePath, "本轮低频检查证据摘要"],
  [resultsPath, "逐请求 JSONL 结果，已后处理误报"],
  [summaryPath, "统计汇总"],
  [reportPath, "中文漏洞报告"],
], "KnownExposureEvidence");
style(shEvidence, shEvidence.getRange("A1:B5"), [420, 520]);

await fs.mkdir(outputDir, { recursive: true });
const inspect = await workbook.inspect({ kind: "table", range: "已验证漏洞!A1:I5", include: "values", tableMaxRows: 5, tableMaxCols: 9, maxChars: 5000 });
console.log(inspect.ndjson);
const errors = await workbook.inspect({ kind: "match", searchTerm: "#REF!|#DIV/0!|#VALUE!|#NAME\\?|#N/A", options: { useRegex: true, maxResults: 100 } });
console.log(errors.ndjson);
for (const sheetName of ["总览", "资产矩阵", "已验证漏洞", "误报剔除"]) {
  const preview = await workbook.render({ sheetName, autoCrop: "all", scale: 1, format: "png" });
  await fs.writeFile(path.join(outputDir, `${sheetName}.png`), new Uint8Array(await preview.arrayBuffer()));
}
const xlsx = await SpreadsheetFile.exportXlsx(workbook);
await xlsx.save(outputPath);
console.log(outputPath);
