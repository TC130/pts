#!/usr/bin/env python3
import json
import os
import re
import subprocess
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin

OUT_DIR = Path("outputs/actuator_followup_20260527")
JSONL = OUT_DIR / "actuator_followup_results.jsonl"
SUMMARY = OUT_DIR / "summary.json"
EVIDENCE = Path("pentest_state/requests/actuator-followup-20260527.txt")
REPORT = Path("pentest_state/report-actuator-followup-20260527.md")

PROXY_HOST = "39.106.140.81:8877"
PROXY_USER = os.environ.get("PENTEST_PROXY_USER", "")
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36"

TARGETS = {
    "https://fm-adx.wostore.cn/": [
        "/actuator",
        "/actuator/health",
        "/actuator/info",
        "/actuator/prometheus",
        "/actuator/beans",
        "/actuator/caches",
        "/actuator/conditions",
        "/actuator/configprops",
        "/actuator/env",
        "/actuator/metrics",
        "/actuator/loggers",
        "/actuator/threaddump",
        "/actuator/logfile",
        "/actuator/mappings",
        "/actuator/scheduledtasks",
        "/actuator/auditevents",
    ],
    "https://sdk-event.wostore.cn/": [
        "/actuator",
        "/actuator/health",
        "/actuator/health/liveness",
        "/actuator/health/readiness",
        "/actuator/info",
        "/actuator/env",
        "/actuator/metrics",
        "/actuator/prometheus",
        "/actuator/beans",
        "/actuator/configprops",
    ],
}

SENSITIVE_PATTERNS = [
    (re.compile(r"(?i)(access[_-]?token|refresh[_-]?token|id[_-]?token|authorization|api[_-]?key|secret|password|passwd|pwd|session[_-]?key|client[_-]?secret)\s*[:=]\s*['\"]?[^'\"\s,;&}]{4,}"), r"\1=REDACTED"),
    (re.compile(r"(?i)(jdbc:[^,}\s]+)"), "jdbc:REDACTED"),
    (re.compile(r"(?i)(redis://[^,}\s]+)"), "redis://REDACTED"),
    (re.compile(r"1[3-9]\d{9}"), "PHONE_REDACTED"),
]


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
            key, value = line.split(":", 1)
            headers.setdefault(key.lower(), []).append(value.strip())
    statuses = [line.strip() for line in lines if line.startswith("HTTP/")]
    return statuses, headers


def extract_body(text: str) -> str:
    blocks = re.split(r"\r?\n\r?\n", text, maxsplit=1)
    return blocks[1] if len(blocks) > 1 else ""


def sanitize(text: str) -> str:
    text = text[:5000]
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    for pattern, repl in SENSITIVE_PATTERNS:
        text = pattern.sub(repl, text)
    return text[:1200]


def curl_get(url: str, byte_range="0-4095"):
    cmd = [
        "curl", "-sS", "-k", "-L",
        "--max-redirs", "1",
        "--connect-timeout", "5",
        "--max-time", "10",
        "--socks5-hostname", PROXY_HOST,
        "--proxy-user", PROXY_USER,
        "-A", UA,
        "-H", "Accept: application/json,text/plain,*/*",
        "-D", "-",
        "--range", byte_range,
        url,
    ]
    started = time.time()
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout = decode(p.stdout)
    statuses, headers = parse_headers(stdout)
    body = extract_body(stdout)
    return {
        "exit": p.returncode,
        "elapsed_sec": round(time.time() - started, 2),
        "error": decode(p.stderr).strip()[:200],
        "status": statuses[-1] if statuses else "",
        "content_type": (headers.get("content-type") or [""])[0],
        "server": (headers.get("server") or [""])[0],
        "body_snippet": sanitize(body),
    }


def classify(path: str, res: dict) -> str:
    status = res["status"]
    body = res["body_snippet"].lower()
    if not status:
        return "无法验证"
    if not any(code in status for code in ("200", "206")):
        return "未开放"
    if path in ("/actuator", "/actuator/health", "/actuator/health/liveness", "/actuator/health/readiness"):
        return "Actuator 基础端点开放"
    if any(key in body for key in ("propertysources", "systemenvironment", "configprops", "contexts", "beans", "# help", "jvm_", "process_", "logger")):
        return "Actuator 敏感端点开放"
    if body:
        return "Actuator 子端点开放需复核"
    return "空响应需复核"


def main():
    if not PROXY_USER:
        raise SystemExit("PENTEST_PROXY_USER is required")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    egress = curl_get("https://icanhazip.com/")
    if "39.106.140.81" not in egress["body_snippet"]:
        raise SystemExit(f"Unexpected egress: {egress['body_snippet']}")

    rows = []
    for origin, paths in TARGETS.items():
        for path in paths:
            time.sleep(0.12)
            url = urljoin(origin, path.lstrip("/"))
            res = curl_get(url)
            row = {
                "origin": origin,
                "path": path,
                "url": url,
                "status": res["status"],
                "content_type": res["content_type"],
                "server": res["server"],
                "error": res["error"],
                "classification": classify(path, res),
                "body_snippet": res["body_snippet"],
            }
            rows.append(row)
            print(json.dumps(row, ensure_ascii=False), flush=True)

    JSONL.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n")
    counts = Counter(r["classification"] for r in rows)
    by_origin = defaultdict(list)
    for row in rows:
        by_origin[row["origin"]].append(row)
    summary = {
        "egress": "39.106.140.81",
        "origins": len(TARGETS),
        "tests": len(rows),
        "classification_counts": dict(counts),
        "sensitive_open_count": counts.get("Actuator 敏感端点开放", 0),
    }
    SUMMARY.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")

    evidence = [
        "# Actuator 深度只读验证证据",
        "",
        f"时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "代理出口：`39.106.140.81`",
        "测试方式：仅对已确认暴露 Actuator 的 2 个 origin 做固定子端点只读 GET；每个响应仅取前 4KB 并脱敏；未请求 heapdump，未下载大文件。",
        "",
        "## 汇总",
        "",
        f"- Origin 数：{summary['origins']}",
        f"- 请求数：{summary['tests']}",
        f"- 分类：{json.dumps(summary['classification_counts'], ensure_ascii=False)}",
        "",
        "## 明细",
        "",
    ]
    for row in rows:
        evidence.append(f"- `{row['url']}`：{row['classification']}；`{row['status'] or row['error']}`；{row['body_snippet'][:500] or '-'}")
    EVIDENCE.write_text("\n".join(evidence) + "\n")

    report = [
        "# Actuator 深度只读验证补充报告",
        "",
        "## 测试边界",
        "",
        "- 仅针对已确认存在 Actuator 未授权暴露的 2 个资产。",
        "- 仅使用 GET 只读验证，低频请求。",
        "- 仅取响应前 4KB 并脱敏，不下载 heapdump 或其他大体量敏感文件。",
        "",
        "## 汇总",
        "",
        f"- 请求数：{summary['tests']}",
        f"- 敏感子端点开放数：{summary['sensitive_open_count']}",
        "",
    ]
    for origin, items in sorted(by_origin.items()):
        report += [f"## {origin}", ""]
        for row in items:
            if row["classification"] in {"Actuator 敏感端点开放", "Actuator 基础端点开放", "Actuator 子端点开放需复核"}:
                report.append(f"- `{row['path']}`：{row['classification']}；响应 `{row['status']}`；摘要：{row['body_snippet'][:260] or '-'}")
        report.append("")
    report += ["## 证据索引", "", f"- 证据摘要：`{EVIDENCE}`", f"- 原始 JSONL：`{JSONL}`"]
    REPORT.write_text("\n".join(report) + "\n")
    print(json.dumps(summary, ensure_ascii=False))
    print(f"REPORT={REPORT}")


if __name__ == "__main__":
    main()
