#!/usr/bin/env python3
import json
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

OUT_DIR = Path("outputs/known_exposure_20260527")
JSONL = OUT_DIR / "known_exposure_results.jsonl"
SUMMARY = OUT_DIR / "summary.json"
EVIDENCE = Path("pentest_state/requests/known-exposure-checks-20260527.txt")
REPORT = Path("pentest_state/report-known-exposure-checks-20260527.md")


def is_success(status: str) -> bool:
    return any(code in status for code in ("200", "206"))


def is_fallback_body(path: str, content_type: str, body: str) -> bool:
    if "text/html" not in content_type.lower():
        return False
    lowered = body.lower()
    markers = [
        "doesn't work properly without javascript enabled",
        "we're sorry but",
        "访问失败，url不存在或已过期",
        "resource is not found",
        "404 not found",
        "找不到页面",
        "whitelabel error page",
        "an unexpected error",
        "an error occurred",
        "云联壹云 .loading-wrapper",
    ]
    if any(marker in lowered for marker in markers):
        return True
    if path.endswith((".env", ".json", ".xml", ".txt", ".map")) and "<html" in lowered:
        return True
    return False


def classify(row: dict) -> str:
    status = row.get("status", "")
    body = row.get("body_snippet", "")
    lowered = body.lower()
    content_type = row.get("content_type", "")
    path = urlsplit(row.get("url", "")).path.lower()
    if not status:
        return "无法验证"
    if not is_success(status):
        return "未暴露"
    if path.endswith(".map") and "text/html" in content_type.lower():
        return "未暴露"
    if is_fallback_body(path, content_type, body):
        return "未暴露"
    if path.endswith(".map") and any(k in lowered for k in ("sources", "webpack", "\"version\"")):
        return "source map 暴露"
    if path.endswith("/.env"):
        env_like = any(k in lowered for k in ("secret", "password", "token", "key", "db_", "redis"))
        return ".env 暴露" if "=" in body and env_like else "200 但内容需复核"
    if "swagger" in path or "api-docs" in path or "openapi" in path:
        return "API 文档暴露" if any(k in lowered for k in ("swagger", "openapi", "\"paths\"", "api-docs")) else "200 但内容需复核"
    if "actuator" in path:
        return "Actuator 暴露" if any(k in lowered for k in ("_links", "\"status\"", "propertysources", "activeprofiles", "management.endpoints")) else "200 但内容需复核"
    if path.endswith("config.json") and any(k in lowered for k in ("api", "baseurl", "appid", "token", "secret")):
        return "前端配置暴露"
    if path.endswith(("robots.txt", "sitemap.xml", "security.txt", "assetlinks.json", "manifest.json", "version", "info", "metrics")) and body:
        return "公开信息文件"
    return "200 但内容需复核"


def render(rows: list[dict]) -> None:
    origins = len({r.get("origin") for r in rows if r.get("origin")})
    counts = Counter(r["classification"] for r in rows)
    notable = [r for r in rows if r["classification"] not in {"未暴露", "无法验证", "200 但内容需复核", "公开信息文件"}]
    public_info = [r for r in rows if r["classification"] == "公开信息文件"]
    summary = {
        "origins": origins,
        "tests": len(rows),
        "classification_counts": dict(counts),
        "notable_count": len(notable),
        "public_info_count": len(public_info),
    }
    SUMMARY.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    JSONL.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n")

    evidence = [
        "# 已知暴露面低频检查证据",
        "",
        "代理出口：已确认为 `39.106.140.81`",
        "测试方式：对已获得响应的 origin 执行固定少量公开路径检查，并对已知 JS 做 source map 检查；非字典爆破；仅取响应前 8KB 并脱敏。",
        "后处理说明：已将 SPA 前端兜底页、404 错误页、网关错误页从候选暴露中剔除。",
        "",
        "## 汇总",
        "",
        f"- Origin 数：{summary['origins']}",
        f"- 请求数：{summary['tests']}",
        f"- 分类：{json.dumps(summary['classification_counts'], ensure_ascii=False)}",
        "",
        "## 重点发现",
        "",
    ]

    report = [
        "# 已知暴露面低频检查报告",
        "",
        "## 测试边界",
        "",
        "- 固定公开路径检查：robots、sitemap、security.txt、Swagger/OpenAPI、Actuator、.env、config、version/info 等。",
        "- Source map 检查仅针对已在页面中发现的 JS 资源。",
        "- 未做目录爆破、未做高频扫描、未下载大文件。",
        "- 已剔除 SPA 前端兜底页、404 错误页、网关错误页造成的 200/206 误报。",
        "",
        "## 汇总",
        "",
        f"- Origin 数：{summary['origins']}",
        f"- 请求数：{summary['tests']}",
        f"- 重点发现数：{summary['notable_count']}",
        f"- 公开信息文件数：{summary['public_info_count']}",
        "",
    ]

    if notable:
        report += ["## 已验证漏洞", ""]
        for r in notable:
            line = f"- `{r['url']}`：{r['classification']}；响应 `{r['status']}`；摘要：{r['body_snippet'][:260] or '-'}"
            report.append(line)
            evidence.append(f"- `{r['url']}`：{r['classification']}；{r['status']}；{r['body_snippet'][:500] or '-'}")
        actuator_by_origin = {}
        for r in notable:
            if r["classification"] == "Actuator 暴露":
                actuator_by_origin.setdefault(r["origin"], []).append(r)
        if actuator_by_origin:
            report += ["", "## 漏洞证明", ""]
            for origin, items in sorted(actuator_by_origin.items()):
                urls = {r["url"]: r for r in items}
                health = next((r for r in items if r["url"].endswith("/actuator/health")), None)
                index = next((r for r in items if r["url"].endswith("/actuator")), None)
                risk = "高危" if origin == "https://fm-adx.wostore.cn/" else "中危"
                endpoints = "、".join(f"`{r['url']}`" for r in items)
                report += [
                    f"### {origin} Spring Boot Actuator 管理端点未授权暴露",
                    "",
                    f"- 风险等级：{risk}",
                    "- 验证状态：已验证，存在漏洞",
                    f"- 受影响资产：`{origin}`",
                    f"- 已验证端点：{endpoints}",
                    "- 论点：Actuator 是应用管理与监控端点，正常情况下不应对公网未认证开放；本次无需登录即可通过 GET 获得 JSON 管理端点索引或健康状态。",
                    f"- 论据 1：`/actuator` 返回 `{index['status'] if index else '-'}`、`{index['content_type'] if index else '-'}`，正文包含 `{(index['body_snippet'][:220] if index else '-').replace('|', '/')}`。",
                ]
                if health:
                    report.append(f"- 论据 2：`/actuator/health` 返回 `{health['status']}`、`{health['content_type']}`，正文包含 `{health['body_snippet'][:220].replace('|', '/')}`。")
                if origin == "https://fm-adx.wostore.cn/":
                    report += [
                        "- 影响：已暴露的索引指向 `prometheus`、`beans`、`caches`、`conditions`、`health`、`info` 等管理/诊断端点；继续访问可能泄露运行时组件、缓存、指标、条件配置和健康细节。本轮为避免扩大数据读取，未继续抓取深层管理端点。",
                        "- 修复建议：将 Actuator 端点限制在内网或管理网段；对 `/actuator/**` 加认证和授权；仅暴露必要的 `health`/`info`，并关闭 `show-details`；对 Prometheus 指标使用独立鉴权或内网采集。",
                    ]
                else:
                    report += [
                        "- 影响：当前至少泄露服务存活状态与可访问管理入口；虽然本轮未发现深层端点索引，但公网未认证开放仍会增加探测面，并可能为后续版本配置变更留下风险。",
                        "- 修复建议：对 `/actuator/**` 加认证和来源限制；如必须开放健康检查，仅暴露最小化的 `/actuator/health`，关闭详细信息和通配健康路径。",
                    ]
                report.append("")
    else:
        report += ["## 可写入报告的候选问题", "", "- 本轮未发现 `.env`、Swagger/OpenAPI、Actuator、source map 等高价值暴露。"]
        evidence.append("- 本轮未发现 `.env`、Swagger/OpenAPI、Actuator、source map 等高价值暴露。")

    if public_info:
        report += ["", "## 公开信息文件观察项", ""]
        for r in public_info[:60]:
            report.append(f"- `{r['url']}`：{r['status']}；{r['body_snippet'][:180] or '-'}")

    false_positive_notes = [
        "## 已剔除误报说明",
        "",
        "- `220.196.214.104:20443`、`cloudgamecm.wostore.cn:18010` 多个敏感路径返回同一份“云联壹云”前端 HTML 壳，包含 loading 样式，不是 `.env`、Swagger 或 Actuator 内容。",
        "- `qyphone.wostore.cn:30443`、`qyphone.wostore.cn:32001` 多个敏感路径返回同一份前端应用壳，正文提示需启用 JavaScript，不是公开信息文件。",
        "- `9cfx.cn`、`lo7.cn` 的 206 响应正文明确提示 URL 不存在或已过期，不作为暴露。",
        "",
    ]
    report += [""] + false_positive_notes + ["## 证据索引", "", f"- 证据摘要：`{EVIDENCE}`", f"- 原始 JSONL：`{JSONL}`"]
    evidence += [""] + false_positive_notes + ["## 原始 JSONL", "", f"- `{JSONL}`"]
    EVIDENCE.write_text("\n".join(evidence) + "\n")
    REPORT.write_text("\n".join(report) + "\n")


def main() -> None:
    rows = [json.loads(line) for line in JSONL.read_text().splitlines() if line.strip()]
    for row in rows:
        row["classification"] = classify(row)
    render(rows)
    print(json.dumps(json.loads(SUMMARY.read_text()), ensure_ascii=False))
    print(f"REPORT={REPORT}")


if __name__ == "__main__":
    main()
