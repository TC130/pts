import fs from "node:fs/promises";
import path from "node:path";
import { SpreadsheetFile, Workbook } from "@oai/artifact-tool";

const resultsPath = process.env.PENTEST_RESULTS_JSONL || "outputs/meeting_batch_20260527/baseline_results.jsonl";
const summaryPath = process.env.PENTEST_SUMMARY_JSON || "outputs/meeting_batch_20260527/summary.json";
const outputDir = path.resolve(process.env.PENTEST_OUTPUT_DIR || "outputs/meeting_batch_20260527");
const outputPath = path.join(outputDir, process.env.PENTEST_OUTPUT_XLSX || "会议批量资产-漏洞矩阵_20260527.xlsx");
const batchTitle = process.env.PENTEST_BATCH_TITLE || "会议批量资产 Web 基线汇总";
const evidencePath = process.env.PENTEST_EVIDENCE_PATH || "pentest_state/requests/meeting-batch-baseline-20260527.txt";
const reportPath = process.env.PENTEST_REPORT_PATH || "pentest_state/report-meeting-batch-20260527.md";

const rows = (await fs.readFile(resultsPath, "utf8"))
  .trim()
  .split(/\n+/)
  .filter(Boolean)
  .map((line) => JSON.parse(line));
const summary = JSON.parse(await fs.readFile(summaryPath, "utf8"));

function latestStatus(r) {
  return (r.status && r.status.length ? r.status[r.status.length - 1] : "");
}

function issueTags(r) {
  if (r.skipped) return "跳过：归属待确认";
  const tags = [];
  const text = `${r.title || ""} ${r.body_snippet || ""}`.toLowerCase();
  if (!latestStatus(r)) tags.push("无法有效验证");
  if (r.url?.startsWith("https://") && r.security_headers_missing?.includes("strict-transport-security")) tags.push("缺少 HSTS");
  if ((r.security_headers_missing || []).length >= 4 && latestStatus(r)) tags.push("缺少多个安全响应头");
  if (text.includes("welcome to nginx") || text.includes("welcome to openresty") || text.includes("whitelabel error page") || text.includes("403 forbidden") || text.includes("404 not found")) tags.push("默认/框架错误页暴露");
  if (latestStatus(r).includes("500")) tags.push("未认证 GET 触发 500");
  if (r.url?.startsWith("http://") && (latestStatus(r).includes("200") || latestStatus(r).includes("206"))) tags.push("HTTP 明文返回内容");
  if (Object.keys(r.access_control_headers || {}).length) tags.push("CORS 响应头需复核");
  if (r.pending_approval_categories?.length) tags.push("待审批交互项");
  return [...new Set(tags)].join("；") || "未发现明确漏洞项";
}

function risk(r) {
  const tags = issueTags(r);
  if (tags.includes("未认证 GET 触发 500")) return "低危";
  if (tags.includes("默认/框架错误页暴露")) return "低危";
  if (tags.includes("缺少 HSTS") || tags.includes("缺少多个安全响应头")) return "低危";
  if (tags.includes("HTTP 明文返回内容")) return "低危";
  return "无";
}

function cleanCell(value) {
  if (typeof value !== "string") return value;
  return value.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g, " ").slice(0, 32000);
}

const assetRows = rows.map((r) => [
  r.raw_url,
  r.url,
  r.skipped ? "已跳过" : "已测试",
  r.skipped ? r.skip_reason : (latestStatus(r) ? "已获得应用层响应" : "无应用层响应"),
  latestStatus(r) || r.error || "-",
  r.server || "-",
  r.title || "-",
  r.content_type || "-",
  r.set_cookie_observed ? "是" : "否",
  (r.security_headers_present || []).join(", ") || "-",
  (r.security_headers_missing || []).join(", ") || "-",
  Object.keys(r.access_control_headers || {}).length ? JSON.stringify(r.access_control_headers) : "-",
  risk(r),
  issueTags(r),
  (r.pending_approval_categories || []).join(", ") || "-",
  r.body_snippet || "-",
]);

const findings = [];
for (const r of rows) {
  if (r.skipped) continue;
  const tags = issueTags(r).split("；").filter(Boolean);
  for (const tag of tags) {
    if (tag === "未发现明确漏洞项" || tag === "无法有效验证" || tag === "待审批交互项" || tag === "CORS 响应头需复核") continue;
    findings.push([
      r.url,
      tag,
      risk(r),
      tag.includes("缺少") || tag.includes("默认") || tag.includes("500") || tag.includes("HTTP 明文") ? "已验证，存在漏洞" : "观察项",
      latestStatus(r) || r.error || "-",
      r.server || "-",
      r.title || "-",
      r.body_snippet || "-",
      evidencePath,
    ]);
  }
}

const pendingRows = rows
  .filter((r) => r.pending_approval_categories?.length)
  .map((r) => [
    r.url,
    r.pending_approval_categories.join(", "),
    "待用户回来审批",
    "本轮仅记录，不执行登录、提交、导出、上传、短信、管理操作或爆破。",
    latestStatus(r) || r.error || "-",
    r.title || "-",
  ]);

const workbook = Workbook.create();
const shSummary = workbook.worksheets.add("总览");
const shAssets = workbook.worksheets.add("资产矩阵");
const shFindings = workbook.worksheets.add("漏洞与配置问题");
const shPending = workbook.worksheets.add("待审批项");
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
  widths.forEach((w, idx) => {
    sheet.getRangeByIndexes(0, idx, 1, 1).getColumn(0).format.columnWidthPx = w;
  });
  sheet.getRange("A1:Z1").format.font.bold = true;
  sheet.getRange("A1:Z1").format.fill.color = "#D9EAF7";
  range.format.autofitRows();
}

shSummary.getRange("A1:H1").merge();
shSummary.getRange("A1").values = [[batchTitle]];
shSummary.getRange("A1").format.font.bold = true;
shSummary.getRange("A1").format.font.size = 18;
shSummary.getRange("A1").format.fill.color = "#1F4E79";
shSummary.getRange("A1").format.font.color = "#FFFFFF";
shSummary.getRange("A3:B14").values = [
  ["测试日期", "2026-05-27"],
  ["代理出口", "39.106.140.81"],
  ["用户提供资产", summary.total],
  ["跳过归属待确认", summary.skipped],
  ["实际只读测试", summary.tested],
  ["获得应用层响应", summary.responded],
  ["无应用层响应", summary.failed],
  ["待审批交互线索", summary.pending],
  ["HTTPS 缺少 HSTS", summary.missing_hsts],
  ["默认/框架错误页", summary.default_pages],
  ["未认证 GET 触发 500", summary.server_error],
  ["HTTP 明文返回内容", summary.plain_content],
];
shSummary.getRange("D3:E9").values = [
  ["类别", "数量"],
  ["获得响应", summary.responded],
  ["无响应", summary.failed],
  ["待审批", summary.pending],
  ["缺少 HSTS", summary.missing_hsts],
  ["默认页", summary.default_pages],
  ["跳过", summary.skipped],
];
const chart = shSummary.charts.add("bar", shSummary.getRange("D3:E9"));
chart.setPosition("G3", "L16");
chart.title = "资产状态概览";
style(shSummary, shSummary.getRange("A1:L16"), [160, 220, 40, 150, 100, 40, 120, 120]);

writeTable(shAssets, "A1", ["原始资产", "实际请求 URL", "测试状态", "连通性", "状态/错误", "Server", "Title", "Content-Type", "Set-Cookie", "已存在安全头", "缺失安全头", "CORS 响应头", "最高风险", "问题标签", "待审批类型", "响应摘要"], assetRows, "MeetingAssets");
style(shAssets, shAssets.getRange(`A1:P${assetRows.length + 1}`), [260, 260, 80, 130, 180, 120, 180, 160, 80, 240, 300, 260, 80, 260, 180, 420]);

writeTable(shFindings, "A1", ["资产", "问题", "风险等级", "验证状态", "状态/错误", "Server", "Title", "论据摘要", "证据文件"], findings, "MeetingFindings");
style(shFindings, shFindings.getRange(`A1:I${Math.max(findings.length + 1, 2)}`), [260, 220, 80, 140, 180, 120, 180, 420, 300]);

writeTable(shPending, "A1", ["资产", "待审批类型", "审批状态", "跳过原因", "当前响应", "Title"], pendingRows, "MeetingPending");
style(shPending, shPending.getRange(`A1:F${pendingRows.length + 1}`), [300, 180, 130, 420, 220, 200]);

writeTable(shEvidence, "A1", ["证据/文件", "说明"], [
  [evidencePath, "中文证据摘要"],
  [resultsPath, "逐资产原始基线 JSONL"],
  [reportPath, "中文 Markdown 报告"],
], "MeetingEvidence");
style(shEvidence, shEvidence.getRange("A1:B4"), [420, 520]);

await fs.mkdir(outputDir, { recursive: true });
const inspect = await workbook.inspect({ kind: "table", range: "资产矩阵!A1:P8", include: "values", tableMaxRows: 8, tableMaxCols: 16, maxChars: 5000 });
console.log(inspect.ndjson);
const errors = await workbook.inspect({ kind: "match", searchTerm: "#REF!|#DIV/0!|#VALUE!|#NAME\\?|#N/A", options: { useRegex: true, maxResults: 100 } });
console.log(errors.ndjson);
for (const sheetName of ["总览", "资产矩阵", "漏洞与配置问题", "待审批项"]) {
  const preview = await workbook.render({ sheetName, autoCrop: "all", scale: 1, format: "png" });
  await fs.writeFile(path.join(outputDir, `${sheetName}.png`), new Uint8Array(await preview.arrayBuffer()));
}
const xlsx = await SpreadsheetFile.exportXlsx(workbook);
await xlsx.save(outputPath);
console.log(outputPath);
