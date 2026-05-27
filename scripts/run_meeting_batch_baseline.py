#!/usr/bin/env python3
import concurrent.futures
import html
import json
import os
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

TARGET_FILE = Path(os.environ.get("PENTEST_TARGET_FILE", "pentest_state/targets/meeting-batch-20260527.txt"))
OUT_DIR = Path(os.environ.get("PENTEST_OUTPUT_DIR", "outputs/meeting_batch_20260527"))
JSONL = OUT_DIR / os.environ.get("PENTEST_JSONL_NAME", "baseline_results.jsonl")
SUMMARY = OUT_DIR / os.environ.get("PENTEST_SUMMARY_NAME", "summary.json")
EVIDENCE = Path(os.environ.get("PENTEST_EVIDENCE_FILE", "pentest_state/requests/meeting-batch-baseline-20260527.txt"))
SKIPPED = OUT_DIR / os.environ.get("PENTEST_SKIPPED_NAME", "skipped_scope.jsonl")
EVIDENCE_TITLE = os.environ.get("PENTEST_EVIDENCE_TITLE", "会议期间大批量资产只读基线测试")

PROXY_HOST = "39.106.140.81:8877"
PROXY_USER = os.environ.get("PENTEST_PROXY_USER", "")
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36"
SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
]
SKIP_HOSTS = {"mp.weixin.qq.com"}
SENSITIVE_QUERY_KEYS = {"access_token", "auth", "key", "secret", "session", "sessionid", "sid", "token"}


def clean_url(raw: str) -> str:
    raw = raw.strip()
    parts = urlsplit(raw)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


def redact_url(raw: str) -> str:
    parts = urlsplit(raw.strip())
    query = parse_qsl(parts.query, keep_blank_values=True)
    redacted = [
        (key, "REDACTED" if key.lower() in SENSITIVE_QUERY_KEYS else value)
        for key, value in query
    ]
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", urlencode(redacted, doseq=True), ""))


def parse_headers(text: str):
    # curl -D - with redirects emits multiple header blocks. Use the last HTTP block.
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


def title_of(body: str):
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if not m:
        return ""
    return html.unescape(re.sub(r"\s+", " ", m.group(1)).strip())[:180]


def classify_pending(url: str, title: str, body: str):
    lower = f"{url} {title} {body[:1000]}".lower()
    hits = []
    patterns = {
        "登录/认证流程": ["login", "signin", "authentication", "adminlogin", "登录", "账号", "密码"],
        "管理后台": ["admin", "manager", "console", "kuboard", "seeyon"],
        "上传/下载功能": ["upload", "download", "上传", "下载"],
        "报表/导出功能": ["reportserver", "report", "export", "报表", "导出"],
        "支付/会员功能": ["unipay", "member", "vip", "支付", "会员"],
    }
    for label, needles in patterns.items():
        if any(n in lower for n in needles):
            hits.append(label)
    return sorted(set(hits))


def decode_output(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def request_target(order: int, raw_url: str):
    url = clean_url(raw_url)
    safe_raw_url = redact_url(raw_url)
    safe_url = redact_url(url)
    host = urlsplit(url).hostname or ""
    if host in SKIP_HOSTS:
        return {
            "order": order,
            "raw_url": safe_raw_url,
            "url": safe_url,
            "skipped": True,
            "skip_reason": "明显第三方平台，归属需用户确认",
        }

    cmd = [
        "curl",
        "-sS",
        "-k",
        "-L",
        "--max-redirs",
        "2",
        "--connect-timeout",
        "5",
        "--max-time",
        "12",
        "--socks5-hostname",
        PROXY_HOST,
        "--proxy-user",
        PROXY_USER,
        "-A",
        UA,
        "-H",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "-D",
        "-",
        "--range",
        "0-65535",
        url,
    ]
    start = time.time()
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    elapsed = round(time.time() - start, 2)
    stdout = decode_output(p.stdout)
    stderr = decode_output(p.stderr)
    statuses, headers = parse_headers(stdout)
    body = extract_body(stdout)
    title = title_of(body)
    body_text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body[:3000])).strip()[:500]
    pending = classify_pending(url, title, body_text)
    return {
        "order": order,
        "raw_url": safe_raw_url,
        "url": safe_url,
        "skipped": False,
        "exit": p.returncode,
        "elapsed_sec": elapsed,
        "error": stderr.strip()[:220],
        "status": statuses[-3:],
        "server": (headers.get("server") or [""])[0],
        "location": (headers.get("location") or [""])[0],
        "content_type": (headers.get("content-type") or [""])[0],
        "set_cookie_observed": "set-cookie" in headers,
        "security_headers_present": [h for h in SECURITY_HEADERS if h in headers],
        "security_headers_missing": [h for h in SECURITY_HEADERS if h not in headers] if statuses else [],
        "access_control_headers": {k: headers[k] for k in headers if k.startswith("access-control-")},
        "title": title,
        "body_snippet": body_text,
        "pending_approval_categories": pending,
    }


def main():
    if not PROXY_USER:
        raise SystemExit("PENTEST_PROXY_USER is required")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    targets = [line.strip() for line in TARGET_FILE.read_text().splitlines() if line.strip() and not line.startswith("#")]

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        futures = {pool.submit(request_target, idx, t): t for idx, t in enumerate(targets)}
        for fut in concurrent.futures.as_completed(futures):
            item = fut.result()
            results.append(item)
            print(json.dumps(item, ensure_ascii=False), flush=True)

    results.sort(key=lambda x: x["order"])
    JSONL.write_text("\n".join(json.dumps(item, ensure_ascii=False) for item in results) + "\n")
    SKIPPED.write_text("\n".join(json.dumps(item, ensure_ascii=False) for item in results if item.get("skipped")) + "\n")

    tested = [r for r in results if not r.get("skipped")]
    responded = [r for r in tested if r.get("status")]
    timed_or_failed = [r for r in tested if not r.get("status")]
    pending = [r for r in tested if r.get("pending_approval_categories")]
    missing_hsts = [r for r in responded if "strict-transport-security" in r.get("security_headers_missing", []) and urlsplit(r["url"]).scheme == "https"]
    cors_suspicious = [r for r in responded if r.get("access_control_headers")]
    default_pages = [
        r for r in responded
        if any(marker in f"{r.get('title', '')} {r.get('body_snippet', '')}".lower() for marker in ["welcome to nginx", "welcome to openresty", "whitelabel error page", "403 forbidden", "404 not found"])
    ]
    server_error = [r for r in responded if any(" 500" in status for status in r.get("status", []))]
    plain_content = [
        r for r in responded
        if urlsplit(r["url"]).scheme == "http" and any((" 200" in status or " 206" in status) for status in r.get("status", []))
    ]

    summary = {
        "total": len(targets),
        "skipped": len(results) - len(tested),
        "tested": len(tested),
        "responded": len(responded),
        "failed": len(timed_or_failed),
        "pending": len(pending),
        "missing_hsts": len(missing_hsts),
        "cors_suspicious": len(cors_suspicious),
        "default_pages": len(default_pages),
        "server_error": len(server_error),
        "plain_content": len(plain_content),
    }
    SUMMARY.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")

    lines = [
        f"# 证据：{EVIDENCE_TITLE}",
        "",
        f"时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"目标数量：{len(targets)}",
        "代理出口：已确认为 `39.106.140.81`",
        "测试方式：每个未跳过目标最多一次只读 GET 基线请求，最多跟随 2 次跳转，未执行登录/提交/爆破/目录枚举。",
        "",
        "## 汇总",
        "",
        f"- 跳过归属需确认目标：{len(results) - len(tested)}",
        f"- 实际只读测试目标：{len(tested)}",
        f"- 获得 HTTP/HTTPS 应用层响应：{len(responded)}",
        f"- 超时/连接失败/未获得应用层响应：{len(timed_or_failed)}",
        f"- 发现需审批后继续的功能线索资产：{len(pending)}",
        f"- HTTPS 响应缺少 HSTS 的资产：{len(missing_hsts)}",
        f"- 返回 Access-Control-* 响应头的资产：{len(cors_suspicious)}",
        "",
        "## 跳过目标",
        "",
    ]
    skipped = [r for r in results if r.get("skipped")]
    if skipped:
        for r in skipped:
            lines.append(f"- `{r['raw_url']}`：{r['skip_reason']}")
    else:
        lines.append("- 无")
    lines += ["", "## 获得响应的目标", ""]
    lines.append("| 目标 | 状态 | Server | 标题 | 缺失安全头 | 待审批线索 |")
    lines.append("|---|---|---|---|---|---|")
    for r in responded:
        lines.append(
            f"| `{r['url']}` | {'; '.join(r['status'])} | {r['server'] or '-'} | {r['title'] or '-'} | {', '.join(r['security_headers_missing']) or '-'} | {', '.join(r['pending_approval_categories']) or '-'} |"
        )
    lines += ["", "## 未获得应用层响应的目标", ""]
    for r in timed_or_failed:
        lines.append(f"- `{r['url']}`：exit={r.get('exit')}，{r.get('error') or '未获得响应'}")
    lines += ["", "## 待用户回来审批的高风险/状态变更类操作", ""]
    if pending:
        for r in pending:
            lines.append(f"- `{r['url']}`：{', '.join(r['pending_approval_categories'])}。本轮仅记录，不执行登录、提交、导出、上传、短信、管理操作或爆破。")
    else:
        lines.append("- 本轮未发现需要进一步审批的交互类操作线索。")
    lines += ["", "## 原始 JSONL", "", f"- `{JSONL}`"]
    EVIDENCE.write_text("\n".join(lines) + "\n")
    print(f"EVIDENCE={EVIDENCE}")


if __name__ == "__main__":
    main()
