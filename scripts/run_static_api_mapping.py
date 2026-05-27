#!/usr/bin/env python3
import html
import json
import os
import re
import subprocess
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

INPUT = Path("outputs/pending_passive_20260527/pending_passive_results.jsonl")
OUT_DIR = Path("outputs/static_api_mapping_20260527")
JSONL = OUT_DIR / "static_api_mapping.jsonl"
SUMMARY = OUT_DIR / "summary.json"
EVIDENCE = Path("pentest_state/requests/static-api-mapping-20260527.txt")
REPORT = Path("pentest_state/report-static-api-mapping-20260527.md")

PROXY_HOST = "39.106.140.81:8877"
PROXY_USER = os.environ.get("PENTEST_PROXY_USER", "")
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36"
SENSITIVE_QUERY_KEYS = {"access_token", "auth", "key", "password", "secret", "session", "sessionid", "sid", "token"}
FOCUS_URLS = {
    "https://qyphone.wostore.cn:32001/",
    "https://speedupload.wostore.cn/",
    "https://member.zlhz.wostore.cn/wcy_game_vip/prd/vipLogin.html",
    "https://h5forphone.wostore.cn/pc/HFExchange.html",
    "https://h5forphone1.wostore.cn/pc/HFExchange.html",
    "https://cloudgame.wostore.cn/cloudgame/download.html",
    "https://wcgcenter.wostore.cn/gameInfos/appDownload/h5.html?chid=gzh",
}
SKIP_STATIC_MARKERS = [
    "jquery", "vue", "element", "chunk-vendors", "runtime-dom", "vant", "echarts",
    "flexible", "layer", "swiper", "moment", "xlsx", "lodash",
]


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


def curl_get(url: str, byte_range: str = "0-1048575"):
    cmd = [
        "curl", "-sS", "-k", "-L",
        "--max-redirs", "2",
        "--connect-timeout", "6",
        "--max-time", "20",
        "--socks5-hostname", PROXY_HOST,
        "--proxy-user", PROXY_USER,
        "-A", UA,
        "-H", "Accept: text/html,application/javascript,text/javascript,text/css,*/*;q=0.8",
        "-D", "-",
        "--range", byte_range,
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
        "status": statuses[-1] if statuses else "",
        "content_type": (headers.get("content-type") or [""])[0],
        "body": extract_body(stdout),
    }


def same_origin(base: str, candidate: str) -> bool:
    a, b = urlsplit(base), urlsplit(candidate)
    return (a.scheme, a.hostname, a.port) == (b.scheme, b.hostname, b.port)


def attr_values(body: str, attr: str):
    return re.findall(rf"""{attr}\s*=\s*["']([^"']+)["']""", body, flags=re.I)


def static_urls(body: str, base_url: str):
    urls = []
    for attr in ("src", "href"):
        for value in attr_values(body, attr):
            if value.startswith(("data:", "javascript:", "mailto:", "tel:", "#")):
                continue
            absolute = urljoin(base_url, html.unescape(value))
            path = urlsplit(absolute).path.lower()
            if same_origin(base_url, absolute) and (path.endswith(".js") or path.endswith(".css")):
                urls.append(absolute)
    # Prefer app/business bundles over vendor libraries.
    uniq = list(dict.fromkeys(urls))
    scored = sorted(
        uniq,
        key=lambda u: (
            any(marker in u.lower() for marker in SKIP_STATIC_MARKERS),
            0 if u.lower().endswith(".js") else 1,
            len(u),
        ),
    )
    return scored[:10]


def normalize_endpoint(base_url: str, value: str):
    value = value.strip().rstrip(".,;)")
    if not value or value.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
        return ""
    if value.startswith("http"):
        if same_origin(base_url, value):
            return redact_url(value)
        return ""
    if value.startswith("//"):
        absolute = f"{urlsplit(base_url).scheme}:{value}"
        return redact_url(absolute) if same_origin(base_url, absolute) else ""
    if value.startswith("/"):
        return redact_url(urljoin(base_url, value))
    return ""


def api_candidates(text: str, base_url: str):
    hits = set()
    patterns = [
        r"""https?://[^"'`\s<>\\)]+""",
        r"""(?<![A-Za-z0-9_])/(?:api|auth|uaa|admin|manager|login|logout|sms|smscode|captcha|verify|upload|download|export|report|pay|member|vip|order|user|account|token|oauth|gateway|service|security|profile|pwd|password)[A-Za-z0-9_./?=&:%${}-]*""",
    ]
    for pattern in patterns:
        for value in re.findall(pattern, text, flags=re.I):
            endpoint = normalize_endpoint(base_url, value)
            if endpoint:
                hits.add(endpoint)
    return sorted(hits)


def method_contexts(text: str, endpoint: str):
    path = urlsplit(endpoint).path
    tail = path.split("/")[-1] or path
    needles = [re.escape(path), re.escape(tail)]
    methods = set()
    params = set()
    snippets = []
    for needle in needles:
        for m in re.finditer(needle, text, flags=re.I):
            start = max(0, m.start() - 220)
            end = min(len(text), m.end() + 260)
            snippet = text[start:end]
            snippets.append(re.sub(r"\s+", " ", snippet)[:420])
            for meth in re.findall(r"""method\s*:\s*["']?(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["']?""", snippet, flags=re.I):
                methods.add(meth.upper())
            for meth in re.findall(r"""\b(get|post|put|delete|patch|head|options)\s*\(""", snippet, flags=re.I):
                methods.add(meth.upper())
            for name in re.findall(r"""(?:params|data)\s*:\s*\{([^}]{1,400})\}""", snippet, flags=re.I):
                for key in re.findall(r"""([A-Za-z_][A-Za-z0-9_]{1,40})\s*:""", name):
                    params.add(key)
    return {
        "methods": sorted(methods),
        "params": sorted(params)[:30],
        "snippets": snippets[:2],
    }


def classify_endpoint(endpoint: str):
    lower = endpoint.lower()
    labels = []
    mapping = {
        "短信/验证码": ["sms", "smscode", "captcha", "verifycode", "sendSms".lower(), "mobile"],
        "认证/登录": ["auth", "login", "logout", "token", "oauth", "ticket", "password", "pwd"],
        "密码找回/修改": ["retrievalpwd", "updatepwd", "password", "pwd"],
        "用户资料": ["/user", "/account", "profile"],
        "报表/导出": ["report", "export"],
        "支付/会员": ["pay", "member", "vip", "order"],
        "上传/下载": ["upload", "download", "apk"],
        "管理后台": ["admin", "manager", "permission", "role"],
    }
    for label, keys in mapping.items():
        if any(k in lower for k in keys):
            labels.append(label)
    return labels or ["其他接口"]


def static_secret_clues(text: str):
    clues = []
    patterns = [
        ("疑似 appId", r"""(?:appId|appid|client_id)\s*[:=]\s*["']([^"']{6,80})["']"""),
        ("疑似密钥字段", r"""(?:secret|appSecret|client_secret|aesKey|AES_KEY|encryptKey)\s*[:=]\s*["']([^"']{8,120})["']"""),
        ("疑似 AK/SK 字段", r"""(?:accessKey|access_key|secretKey|secret_key)\s*[:=]\s*["']([^"']{8,120})["']"""),
    ]
    for label, pattern in patterns:
        for value in re.findall(pattern, text, flags=re.I):
            safe = value[:4] + "***" + value[-4:] if len(value) > 10 else "***"
            clues.append({"type": label, "value_masked": safe})
    return clues[:20]


def load_focus():
    rows = []
    if INPUT.exists():
        for line in INPUT.read_text().splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("url") in FOCUS_URLS:
                rows.append(row)
    known = {row["url"] for row in rows}
    for url in FOCUS_URLS - known:
        rows.append({"url": url, "categories": ["后续重点"], "page": {}, "static_assets_fetched": []})
    return sorted(rows, key=lambda r: r["url"])


def analyze(row):
    url = row["url"]
    page = curl_get(url)
    body = page["body"]
    urls = static_urls(body, url)
    # Include previously discovered static assets if present.
    for item in row.get("static_assets_fetched") or []:
        u = item.get("url")
        if u and u not in urls and same_origin(url, u):
            urls.append(u)
    urls = list(dict.fromkeys(urls))[:10]

    static_results = []
    combined = body[:1200000]
    for static_url in urls:
        static = curl_get(static_url)
        static_results.append({
            "url": redact_url(static_url),
            "status": static["status"],
            "content_type": static["content_type"],
            "bytes_observed": len(static["body"].encode("utf-8", errors="ignore")),
            "error": static["error"],
        })
        combined += "\n" + static["body"][:1200000]

    endpoints = []
    for endpoint in api_candidates(combined, url):
        ctx = method_contexts(combined, endpoint)
        endpoints.append({
            "url": endpoint,
            "labels": classify_endpoint(endpoint),
            "methods_observed": ctx["methods"],
            "params_observed": ctx["params"],
            "snippets": ctx["snippets"],
        })

    label_counts = Counter(label for e in endpoints for label in e["labels"])
    return {
        "url": redact_url(url),
        "categories": row.get("categories") or [],
        "page_status": page["status"] or page["error"],
        "static_assets": static_results,
        "endpoint_count": len(endpoints),
        "label_counts": dict(sorted(label_counts.items())),
        "endpoints": endpoints[:120],
        "secret_clues": static_secret_clues(combined),
    }


def main():
    if not PROXY_USER:
        raise SystemExit("PENTEST_PROXY_USER is required")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rows = load_focus()
    results = [analyze(row) for row in rows]
    JSONL.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in results) + "\n")
    summary = {
        "targets": len(results),
        "targets_with_endpoints": sum(1 for r in results if r["endpoint_count"]),
        "endpoint_total": sum(r["endpoint_count"] for r in results),
        "secret_clue_total": sum(len(r["secret_clues"]) for r in results),
    }
    SUMMARY.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")

    lines = [
        "# 静态 API 地图证据",
        "",
        f"时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "代理出口：已确认为 `39.106.140.81`",
        "测试方式：仅 GET 重点页面及同源静态 JS/CSS，进行离线正则分析；未调用业务 API，未提交表单，未触发短信、支付、上传、导出或密码流程。",
        "",
        "## 汇总",
        "",
        f"- 重点资产：{summary['targets']}",
        f"- 发现接口候选的资产：{summary['targets_with_endpoints']}",
        f"- 接口候选总数：{summary['endpoint_total']}",
        f"- 静态疑似密钥/标识线索：{summary['secret_clue_total']}",
        "",
    ]
    report = [
        "# 重点资产静态 API 地图报告",
        "",
        "## 测试边界",
        "",
        "- 本轮仅抓取重点页面和同源静态资源做离线分析。",
        "- 未调用候选业务接口，未发送短信，未登录，未提交表单，未触发支付/会员/导出/上传/密码修改。",
        "",
        "## 结论摘要",
        "",
        f"- 重点资产：{summary['targets']}",
        f"- 发现接口候选的资产：{summary['targets_with_endpoints']}",
        f"- 接口候选总数：{summary['endpoint_total']}",
        f"- 静态疑似密钥/标识线索：{summary['secret_clue_total']}",
        "",
        "说明：以下内容是静态线索，不等于漏洞成立。只有后续对接口鉴权、限流、重放、越权等进行低频验证后，才能写成“已验证，存在漏洞”。",
        "",
    ]
    for r in results:
        lines.append(f"### `{r['url']}`")
        lines.append("")
        lines.append(f"- 页面响应：{r['page_status']}")
        lines.append(f"- 静态资源数：{len(r['static_assets'])}")
        lines.append(f"- 接口候选数：{r['endpoint_count']}")
        lines.append(f"- 标签统计：{json.dumps(r['label_counts'], ensure_ascii=False) if r['label_counts'] else '-'}")
        if r["secret_clues"]:
            lines.append(f"- 疑似敏感静态线索：{json.dumps(r['secret_clues'], ensure_ascii=False)}")
        for e in r["endpoints"][:35]:
            lines.append(f"  - `{e['url']}` [{', '.join(e['labels'])}] method={','.join(e['methods_observed']) or '?'} params={','.join(e['params_observed']) or '-'}")
        lines.append("")

        report.append(f"## `{r['url']}`")
        report.append("")
        report.append(f"- 页面响应：{r['page_status']}")
        report.append(f"- 接口候选数：{r['endpoint_count']}")
        report.append(f"- 类型分布：{json.dumps(r['label_counts'], ensure_ascii=False) if r['label_counts'] else '-'}")
        if r["secret_clues"]:
            report.append(f"- 静态疑似密钥/标识线索：{json.dumps(r['secret_clues'], ensure_ascii=False)}")
        risky = [e for e in r["endpoints"] if any(label in e["labels"] for label in ["短信/验证码", "密码找回/修改", "认证/登录", "用户资料", "支付/会员"])]
        if risky:
            report.append("- 后续优先验证方向：")
            for e in risky[:12]:
                report.append(f"  - `{e['url']}`：{', '.join(e['labels'])}；静态方法：{','.join(e['methods_observed']) or '未识别'}；静态参数：{', '.join(e['params_observed']) or '-'}")
        else:
            report.append("- 后续优先验证方向：本轮未识别到高价值接口候选。")
        report.append("")

    lines += ["## 原始 JSONL", "", f"- `{JSONL}`"]
    report += ["## 证据索引", "", f"- 证据摘要：`{EVIDENCE}`", f"- 原始 JSONL：`{JSONL}`"]
    EVIDENCE.write_text("\n".join(lines) + "\n")
    REPORT.write_text("\n".join(report) + "\n")
    print(json.dumps(summary, ensure_ascii=False))
    print(f"EVIDENCE={EVIDENCE}")
    print(f"REPORT={REPORT}")


if __name__ == "__main__":
    main()
