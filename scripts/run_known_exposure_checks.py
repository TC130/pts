#!/usr/bin/env python3
import json
import os
import re
import subprocess
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

OUT_DIR = Path("outputs/known_exposure_20260527")
JSONL = OUT_DIR / "known_exposure_results.jsonl"
SUMMARY = OUT_DIR / "summary.json"
EVIDENCE = Path("pentest_state/requests/known-exposure-checks-20260527.txt")
REPORT = Path("pentest_state/report-known-exposure-checks-20260527.md")

PROXY_HOST = "39.106.140.81:8877"
PROXY_USER = os.environ.get("PENTEST_PROXY_USER", "")
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36"

BASELINE_FILES = [
    Path("outputs/meeting_batch_20260527/baseline_results.jsonl"),
    Path("outputs/supplemental_batch_20260527/baseline_results.jsonl"),
]
STATIC_FILES = [
    Path("outputs/pending_passive_20260527/pending_passive_results.jsonl"),
    Path("outputs/static_api_mapping_20260527/static_api_mapping.jsonl"),
]

KNOWN_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/.well-known/assetlinks.json",
    "/manifest.json",
    "/swagger-ui.html",
    "/swagger-ui/index.html",
    "/swagger/index.html",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/openapi.json",
    "/swagger.json",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/metrics",
    "/.env",
    "/config.json",
    "/version",
    "/info",
]

SENSITIVE_PATTERNS = [
    (re.compile(r"(?i)(access[_-]?token|refresh[_-]?token|id[_-]?token|authorization|api[_-]?key|secret|password|passwd|pwd|session[_-]?key|client[_-]?secret)\s*[:=]\s*['\"]?[^'\"\s,;&]{4,}"), r"\1=REDACTED"),
    (re.compile(r"(?i)(access_token=)[^&\s\"']+"), r"\1REDACTED"),
    (re.compile(r"1[3-9]\d{9}"), "PHONE_REDACTED"),
]


def redact_url(raw: str) -> str:
    parts = urlsplit(raw.strip())
    query = parse_qsl(parts.query, keep_blank_values=True)
    redacted = []
    for key, value in query:
        if key.lower() in {"access_token", "auth", "code", "key", "password", "secret", "session", "sid", "ticket", "token"}:
            value = "REDACTED"
        redacted.append((key, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", urlencode(redacted, doseq=True), ""))


def sanitize(text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", text[:5000])
    text = re.sub(r"\s+", " ", text).strip()
    for pattern, repl in SENSITIVE_PATTERNS:
        text = pattern.sub(repl, text)
    return text[:1000]


def decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def parse_headers(text: str):
    blocks = re.split(r"\r?\n\r?\n", text)
    header_blocks = [b for b in blocks if b.startswith("HTTP/")]
    head = header_blocks[-1] if header_blocks else (blocks[0] if blocks else "")
    lines = head.splitlines()
    headers = {}
    for line in lines:
        if ":" in line:
            k, v = line.split(":", 1)
            headers.setdefault(k.lower(), []).append(v.strip())
    statuses = [line.strip() for line in lines if line.startswith("HTTP/")]
    return statuses, headers


def extract_body(text: str) -> str:
    blocks = re.split(r"\r?\n\r?\n", text, maxsplit=1)
    return blocks[1] if len(blocks) > 1 else ""


def curl_get(url: str, byte_range="0-8191"):
    cmd = [
        "curl", "-sS", "-k", "-L",
        "--max-redirs", "1",
        "--connect-timeout", "5",
        "--max-time", "10",
        "--socks5-hostname", PROXY_HOST,
        "--proxy-user", PROXY_USER,
        "-A", UA,
        "-H", "Accept: text/html,application/json,text/plain,*/*",
        "-D", "-",
        "--range", byte_range,
        url,
    ]
    start = time.time()
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout = decode(p.stdout)
    statuses, headers = parse_headers(stdout)
    body = extract_body(stdout)
    return {
        "exit": p.returncode,
        "elapsed_sec": round(time.time() - start, 2),
        "error": decode(p.stderr).strip()[:180],
        "status": statuses[-1] if statuses else "",
        "content_type": (headers.get("content-type") or [""])[0],
        "server": (headers.get("server") or [""])[0],
        "body": body,
        "body_snippet": sanitize(body),
    }


def origin_of(url: str):
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "/", "", ""))


def load_origins():
    origins = {}
    for file in BASELINE_FILES:
        if not file.exists():
            continue
        for line in file.read_text().splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("skipped") or not row.get("status"):
                continue
            url = row.get("url")
            if url and url.startswith(("http://", "https://")):
                origins.setdefault(origin_of(url), set()).add(row.get("raw_url", url))
    return origins


def load_sourcemap_targets():
    urls = set()
    for file in STATIC_FILES:
        if not file.exists():
            continue
        for line in file.read_text().splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            for item in row.get("static_assets_fetched", []) or row.get("static_assets", []):
                u = item.get("url")
                if u and u.endswith(".js") and not u.endswith(".map"):
                    urls.add(u + ".map")
    return sorted(urls)[:120]


def classify(url: str, res: dict):
    status = res["status"]
    body = res["body_snippet"].lower()
    content_type = res["content_type"].lower()
    path = urlsplit(url).path.lower()
    if not status:
        return "无法验证"
    if not any(code in status for code in ["200", "206"]):
        return "未暴露"
    if path.endswith(".map") and "text/html" in content_type:
        return "未暴露"
    if is_fallback_body(path, content_type, body):
        return "未暴露"
    if path.endswith(".map") and ("sources" in body or "webpack" in body or "version" in body):
        return "source map 暴露"
    if path.endswith("/.env") and ("=" in body and any(k in body for k in ["secret", "password", "token", "key", "db_", "redis"])):
        return ".env 暴露"
    if "swagger" in path or "api-docs" in path or "openapi" in path:
        if any(k in body for k in ["swagger", "openapi", "\"paths\"", "api-docs"]):
            return "API 文档暴露"
    if "actuator" in path:
        if any(k in body for k in ["_links", "status", "propertysources", "activeprofiles", "management.endpoints"]):
            return "Actuator 暴露"
    if path.endswith("config.json") and any(k in body for k in ["api", "baseurl", "appid", "token", "secret"]):
        return "前端配置暴露"
    if path.endswith(("robots.txt", "sitemap.xml", "security.txt", "assetlinks.json", "manifest.json", "version", "info", "metrics")):
        if body:
            return "公开信息文件"
    return "200 但内容需复核"


def is_fallback_body(path: str, content_type: str, body: str) -> bool:
    if "text/html" not in content_type:
        return False
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
    if any(marker in body for marker in markers):
        return True
    if path.endswith((".env", ".json", ".xml", ".txt", ".map")) and "<html" in body:
        return True
    return False


def main():
    if not PROXY_USER:
        raise SystemExit("PENTEST_PROXY_USER is required")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    origins = load_origins()
    tests = []
    for origin in sorted(origins):
        for path in KNOWN_PATHS:
            tests.append({"kind": "known-path", "origin": origin, "url": urljoin(origin, path.lstrip("/"))})
    for url in load_sourcemap_targets():
        tests.append({"kind": "sourcemap", "origin": origin_of(url), "url": url})

    results = []
    for idx, test in enumerate(tests, 1):
        time.sleep(0.08)
        res = curl_get(test["url"])
        item = {
            "kind": test["kind"],
            "origin": test["origin"],
            "url": redact_url(test["url"]),
            "status": res["status"],
            "content_type": res["content_type"],
            "server": res["server"],
            "error": res["error"],
            "classification": classify(test["url"], res),
            "body_snippet": res["body_snippet"],
        }
        results.append(item)
        print(json.dumps(item, ensure_ascii=False), flush=True)

    JSONL.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in results) + "\n")
    counts = Counter(r["classification"] for r in results)
    notable = [r for r in results if r["classification"] not in {"未暴露", "无法验证", "200 但内容需复核", "公开信息文件"}]
    public_info = [r for r in results if r["classification"] == "公开信息文件"]
    summary = {
        "origins": len(origins),
        "tests": len(results),
        "classification_counts": dict(counts),
        "notable_count": len(notable),
        "public_info_count": len(public_info),
    }
    SUMMARY.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")

    lines = [
        "# 已知暴露面低频检查证据",
        "",
        f"时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "代理出口：已确认为 `39.106.140.81`",
        "测试方式：对已获得响应的 origin 执行固定少量公开路径检查，并对已知 JS 做 source map 检查；非字典爆破；仅取响应前 8KB 并脱敏。",
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
        report += ["## 可写入报告的候选问题", ""]
        for r in notable:
            report.append(f"- `{r['url']}`：{r['classification']}；响应 `{r['status']}`；摘要：{r['body_snippet'][:260] or '-'}")
            lines.append(f"- `{r['url']}`：{r['classification']}；{r['status']}；{r['body_snippet'][:500] or '-'}")
    else:
        report += ["## 可写入报告的候选问题", "", "- 本轮未发现 `.env`、Swagger/OpenAPI、Actuator、source map 等高价值暴露。"]
        lines.append("- 本轮未发现 `.env`、Swagger/OpenAPI、Actuator、source map 等高价值暴露。")
    if public_info:
        report += ["", "## 公开信息文件观察项", ""]
        for r in public_info[:60]:
            report.append(f"- `{r['url']}`：{r['status']}；{r['body_snippet'][:180] or '-'}")
    report += ["", "## 证据索引", "", f"- 证据摘要：`{EVIDENCE}`", f"- 原始 JSONL：`{JSONL}`"]
    lines += ["", "## 原始 JSONL", "", f"- `{JSONL}`"]
    EVIDENCE.write_text("\n".join(lines) + "\n")
    REPORT.write_text("\n".join(report) + "\n")
    print(json.dumps(summary, ensure_ascii=False))
    print(f"EVIDENCE={EVIDENCE}")
    print(f"REPORT={REPORT}")


if __name__ == "__main__":
    main()
