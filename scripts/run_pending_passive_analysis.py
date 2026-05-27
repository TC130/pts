#!/usr/bin/env python3
import concurrent.futures
import html
import json
import os
import re
import subprocess
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

SOURCE_JSONL = [
    Path("outputs/meeting_batch_20260527/baseline_results.jsonl"),
    Path("outputs/supplemental_batch_20260527/baseline_results.jsonl"),
]
OUT_DIR = Path("outputs/pending_passive_20260527")
JSONL = OUT_DIR / "pending_passive_results.jsonl"
SUMMARY = OUT_DIR / "summary.json"
EVIDENCE = Path("pentest_state/requests/pending-passive-analysis-20260527.txt")
REPORT = Path("pentest_state/report-pending-passive-20260527.md")

PROXY_HOST = "39.106.140.81:8877"
PROXY_USER = os.environ.get("PENTEST_PROXY_USER", "")
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36"
SENSITIVE_QUERY_KEYS = {"access_token", "auth", "key", "password", "secret", "session", "sessionid", "sid", "token"}
MAX_STATIC_PER_TARGET = 5
MAX_ENDPOINTS = 80
MAX_ROUTES = 80


def redact_url(raw: str) -> str:
    parts = urlsplit(raw.strip())
    query = parse_qsl(parts.query, keep_blank_values=True)
    redacted = [
        (key, "REDACTED" if key.lower() in SENSITIVE_QUERY_KEYS else value)
        for key, value in query
    ]
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", urlencode(redacted, doseq=True), ""))


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


def title_of(body: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if not m:
        return ""
    return html.unescape(re.sub(r"\s+", " ", m.group(1)).strip())[:180]


def curl_get(url: str, max_time: int = 15, byte_range: str = "0-262143"):
    cmd = [
        "curl",
        "-sS",
        "-k",
        "-L",
        "--max-redirs",
        "2",
        "--connect-timeout",
        "6",
        "--max-time",
        str(max_time),
        "--socks5-hostname",
        PROXY_HOST,
        "--proxy-user",
        PROXY_USER,
        "-A",
        UA,
        "-H",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,application/javascript,text/javascript,text/css,*/*;q=0.8",
        "-D",
        "-",
        "--range",
        byte_range,
        url,
    ]
    start = time.time()
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout = decode(p.stdout)
    statuses, headers = parse_headers(stdout)
    return {
        "exit": p.returncode,
        "elapsed_sec": round(time.time() - start, 2),
        "error": decode(p.stderr).strip()[:240],
        "status": statuses[-3:],
        "headers": headers,
        "body": extract_body(stdout),
    }


def load_pending_targets():
    merged = {}
    categories = defaultdict(set)
    for file in SOURCE_JSONL:
        if not file.exists():
            continue
        for line in file.read_text().splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            cats = row.get("pending_approval_categories") or []
            if not cats:
                continue
            url = row["url"]
            merged.setdefault(url, row)
            for cat in cats:
                categories[url].add(cat)
    return [
        {
            "url": url,
            "safe_url": redact_url(url),
            "categories": sorted(categories[url]),
        }
        for url in sorted(merged)
    ]


def same_origin(base: str, candidate: str) -> bool:
    a, b = urlsplit(base), urlsplit(candidate)
    return (a.scheme, a.hostname, a.port) == (b.scheme, b.hostname, b.port)


def extract_attr_values(body: str, attr: str):
    return re.findall(rf"""{attr}\s*=\s*["']([^"']+)["']""", body, flags=re.I)


def extract_forms(body: str, base_url: str):
    forms = []
    for block in re.findall(r"<form\b[^>]*>.*?</form>", body, flags=re.I | re.S):
        action = (re.search(r"""action\s*=\s*["']([^"']*)["']""", block, re.I) or [None, ""])[1]
        method = (re.search(r"""method\s*=\s*["']([^"']*)["']""", block, re.I) or [None, "GET"])[1].upper()
        names = sorted(set(re.findall(r"""(?:name|id)\s*=\s*["']([^"']{1,80})["']""", block, re.I)))[:20]
        forms.append({
            "method": method,
            "action": redact_url(urljoin(base_url, action or base_url)),
            "fields": names,
        })
    return forms[:12]


def clean_candidate(value: str):
    value = html.unescape(value).strip()
    if not value or value.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
        return ""
    return value


def extract_static_urls(body: str, base_url: str):
    candidates = []
    for attr in ("src", "href"):
        for value in extract_attr_values(body, attr):
            value = clean_candidate(value)
            if not value:
                continue
            absolute = urljoin(base_url, value)
            path = urlsplit(absolute).path.lower()
            if same_origin(base_url, absolute) and (path.endswith(".js") or path.endswith(".css")):
                candidates.append(absolute)
    return list(dict.fromkeys(candidates))[:MAX_STATIC_PER_TARGET]


def extract_links(body: str, base_url: str):
    links = []
    for value in extract_attr_values(body, "href"):
        value = clean_candidate(value)
        if not value:
            continue
        absolute = urljoin(base_url, value)
        if same_origin(base_url, absolute):
            links.append(redact_url(absolute))
    return sorted(set(links))[:60]


def endpoint_candidates(text: str, base_url: str):
    hits = set()
    patterns = [
        r"""https?://[^"'`\s<>\\)]+""",
        r"""(?<![A-Za-z0-9_])/(?:api|auth|uaa|admin|manager|login|logout|sms|captcha|verify|upload|download|export|report|pay|member|vip|order|user|account|token|oauth|gateway|service|security)[A-Za-z0-9_./?=&:%-]*""",
    ]
    for pattern in patterns:
        for hit in re.findall(pattern, text, flags=re.I):
            hit = hit.rstrip(".,;)")
            if hit.startswith("http"):
                if same_origin(base_url, hit):
                    hits.add(redact_url(hit))
            else:
                hits.add(redact_url(urljoin(base_url, hit)))
    return sorted(hits)[:MAX_ENDPOINTS]


def route_candidates(text: str):
    hits = set()
    patterns = [
        r"""(?:path|redirect|component|name)\s*:\s*["']([^"']{1,120})["']""",
        r"""(?:router\.push|navigateTo|location\.href)\s*\(\s*["']([^"']{1,120})["']""",
    ]
    for pattern in patterns:
        for hit in re.findall(pattern, text, flags=re.I):
            if "/" in hit and not hit.startswith(("http://", "https://")):
                hits.add(hit)
    return sorted(hits)[:MAX_ROUTES]


def keyword_hits(text: str):
    labels = {
        "登录/认证": ["login", "signin", "password", "captcha", "oauth", "token", "session", "auth", "登录", "验证码"],
        "短信/验证码": ["sms", "mobile", "phone", "verifycode", "captcha", "短信", "手机号", "验证码"],
        "上传/下载": ["upload", "download", "file", "apk", "上传", "下载"],
        "报表/导出": ["report", "export", "excel", "csv", "导出", "报表"],
        "支付/会员": ["pay", "payment", "order", "member", "vip", "支付", "会员", "订单"],
        "管理后台": ["admin", "manager", "console", "role", "permission", "用户管理", "权限"],
    }
    lower = text.lower()
    return [label for label, keys in labels.items() if any(key.lower() in lower for key in keys)]


def analyze_target(item):
    page = curl_get(item["url"])
    body = page["body"]
    headers = page["headers"]
    content_type = (headers.get("content-type") or [""])[0]
    static_urls = extract_static_urls(body, item["url"]) if body else []
    forms = extract_forms(body, item["url"]) if body else []
    links = extract_links(body, item["url"]) if body else []
    combined_text = body[:600000]
    fetched_static = []

    for static_url in static_urls:
        static = curl_get(static_url, max_time=12, byte_range="0-196607")
        static_body = static["body"]
        static_text = static_body[:300000]
        combined_text += "\n" + static_text
        fetched_static.append({
            "url": redact_url(static_url),
            "status": static["status"][-1] if static["status"] else "",
            "content_type": (static["headers"].get("content-type") or [""])[0],
            "bytes_observed": len(static_body.encode("utf-8", errors="ignore")),
            "error": static["error"],
        })

    return {
        "url": item["safe_url"],
        "categories": item["categories"],
        "page": {
            "exit": page["exit"],
            "status": page["status"][-1] if page["status"] else "",
            "elapsed_sec": page["elapsed_sec"],
            "error": page["error"],
            "title": title_of(body),
            "content_type": content_type,
            "server": (headers.get("server") or [""])[0],
            "set_cookie_observed": "set-cookie" in headers,
        },
        "forms": forms,
        "same_origin_links": links,
        "static_assets_fetched": fetched_static,
        "endpoint_candidates": endpoint_candidates(combined_text, item["url"]),
        "route_candidates": route_candidates(combined_text),
        "keyword_hits": keyword_hits(combined_text),
    }


def main():
    if not PROXY_USER:
        raise SystemExit("PENTEST_PROXY_USER is required")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    targets = load_pending_targets()
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = {pool.submit(analyze_target, item): item for item in targets}
        for fut in concurrent.futures.as_completed(futures):
            result = fut.result()
            results.append(result)
            print(json.dumps(result, ensure_ascii=False), flush=True)
    results.sort(key=lambda x: x["url"])

    JSONL.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in results) + "\n")
    responded = [r for r in results if r["page"]["status"]]
    with_forms = [r for r in results if r["forms"]]
    with_endpoints = [r for r in results if r["endpoint_candidates"]]
    with_static = [r for r in results if r["static_assets_fetched"]]
    summary = {
        "total_unique_pending": len(results),
        "responded": len(responded),
        "failed": len(results) - len(responded),
        "with_forms": len(with_forms),
        "with_endpoint_candidates": len(with_endpoints),
        "with_static_assets_fetched": len(with_static),
    }
    SUMMARY.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")

    lines = [
        "# 待审批资产低风险被动分析证据",
        "",
        f"时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "代理出口：已确认为 `39.106.140.81`",
        "测试方式：仅 GET 待审批 URL 及少量同源 JS/CSS 静态资源；未登录、未提交表单、未上传、未导出、未发送短信、未触发支付/会员动作。",
        "",
        "## 汇总",
        "",
        f"- 去重后待审批资产：{summary['total_unique_pending']}",
        f"- 获得应用层响应：{summary['responded']}",
        f"- 未获得应用层响应：{summary['failed']}",
        f"- 发现表单结构：{summary['with_forms']}",
        f"- 发现疑似接口/路由线索：{summary['with_endpoint_candidates']}",
        f"- 拉取同源静态资源：{summary['with_static_assets_fetched']}",
        "",
        "## 逐资产线索",
        "",
    ]
    report_lines = [
        "# 待审批资产低风险被动分析报告",
        "",
        "## 测试边界",
        "",
        "- 本轮已获用户批准继续低风险分析。",
        "- 仅访问待审批 URL 和少量同源静态 JS/CSS。",
        "- 未执行登录、表单提交、上传、导出、短信、支付、会员开通、爆破或目录枚举。",
        "",
        "## 汇总",
        "",
        f"- 去重后待审批资产：{summary['total_unique_pending']}",
        f"- 获得响应：{summary['responded']}",
        f"- 未获得响应：{summary['failed']}",
        f"- 存在表单结构：{summary['with_forms']}",
        f"- 存在疑似接口/路由线索：{summary['with_endpoint_candidates']}",
        "",
        "## 资产分流建议",
        "",
    ]
    for r in results:
        page = r["page"]
        lines.append(f"### `{r['url']}`")
        lines.append("")
        lines.append(f"- 类型：{', '.join(r['categories'])}")
        lines.append(f"- 响应：{page['status'] or page['error'] or '无响应'}")
        lines.append(f"- 标题：{page['title'] or '-'}")
        lines.append(f"- Set-Cookie：{'观察到' if page['set_cookie_observed'] else '未观察到'}")
        lines.append(f"- 表单数量：{len(r['forms'])}")
        lines.append(f"- 同源静态资源抓取：{len(r['static_assets_fetched'])}")
        lines.append(f"- 疑似接口：{', '.join(r['endpoint_candidates'][:12]) or '-'}")
        lines.append(f"- 前端路由：{', '.join(r['route_candidates'][:12]) or '-'}")
        lines.append(f"- 关键词命中：{', '.join(r['keyword_hits']) or '-'}")
        lines.append("")

        report_lines.append(f"### `{r['url']}`")
        report_lines.append("")
        report_lines.append(f"- 初始类型：{', '.join(r['categories'])}")
        report_lines.append(f"- 当前响应：{page['status'] or page['error'] or '无响应'}")
        report_lines.append(f"- 页面标题：{page['title'] or '-'}")
        report_lines.append(f"- 观察到表单：{len(r['forms'])} 个")
        report_lines.append(f"- 疑似接口/路由：接口 {len(r['endpoint_candidates'])} 条，前端路由 {len(r['route_candidates'])} 条")
        if r["forms"] or any(k in r["keyword_hits"] for k in ["登录/认证", "短信/验证码", "报表/导出", "支付/会员"]):
            report_lines.append("- 建议：仍需保持审批门槛；下一步如要验证接口权限、登录、导出、短信或支付流程，需要单独确认。")
        elif page["status"]:
            report_lines.append("- 建议：可继续做只读代码/路由审计，暂未看到必须提交数据才能判断的证据。")
        else:
            report_lines.append("- 建议：当前代理路径无响应，暂不继续深挖。")
        report_lines.append("")

    lines += ["## 原始 JSONL", "", f"- `{JSONL}`"]
    report_lines += ["## 证据索引", "", f"- 证据摘要：`{EVIDENCE}`", f"- 原始 JSONL：`{JSONL}`"]
    EVIDENCE.write_text("\n".join(lines) + "\n")
    REPORT.write_text("\n".join(report_lines) + "\n")
    print(f"EVIDENCE={EVIDENCE}")
    print(f"REPORT={REPORT}")


if __name__ == "__main__":
    main()
