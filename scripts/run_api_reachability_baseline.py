#!/usr/bin/env python3
import json
import os
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

INPUT = Path("outputs/static_api_mapping_20260527/static_api_mapping.jsonl")
OUT_DIR = Path("outputs/api_reachability_20260527")
JSONL = OUT_DIR / "api_reachability_results.jsonl"
SUMMARY = OUT_DIR / "summary.json"
EVIDENCE = Path("pentest_state/requests/api-reachability-baseline-20260527.txt")
REPORT = Path("pentest_state/report-api-reachability-baseline-20260527.md")

PROXY_HOST = "39.106.140.81:8877"
PROXY_USER = os.environ.get("PENTEST_PROXY_USER", "")
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36"
SENSITIVE_QUERY_KEYS = {"access_token", "auth", "code", "key", "password", "secret", "session", "sessionid", "sid", "ticket", "token"}

FOCUS_ENDPOINT_HINTS = [
    "captcha",
    "smscode",
    "sendSms",
    "login",
    "accessToken",
    "retrievalPwd",
    "updatePwd",
    "user/get",
    "user/update",
    "useragreement",
    "privacyagreement",
    "getWeixinSignInfo",
]
GET_DENY_HINTS = [
    "logout",
    "sendSms",
    "smscode",
    "update",
    "upload",
    "pay",
    "order",
    "vip",
    "member/open",
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


def curl_request(method: str, url: str):
    cmd = [
        "curl", "-sS", "-k", "-L",
        "--max-redirs", "0",
        "--connect-timeout", "5",
        "--max-time", "10",
        "--socks5-hostname", PROXY_HOST,
        "--proxy-user", PROXY_USER,
        "-A", UA,
        "-X", method,
        "-H", "Accept: application/json,text/plain,*/*",
        "-H", "Origin: https://audit.invalid",
        "-D", "-",
        "--range", "0-4095",
        url,
    ]
    start = time.time()
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout = decode(p.stdout)
    statuses, headers = parse_headers(stdout)
    body = extract_body(stdout)
    body_text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body[:1200])).strip()
    return {
        "method": method,
        "exit": p.returncode,
        "elapsed_sec": round(time.time() - start, 2),
        "error": decode(p.stderr).strip()[:200],
        "status": statuses[-1] if statuses else "",
        "content_type": (headers.get("content-type") or [""])[0],
        "allow": (headers.get("allow") or [""])[0],
        "access_control": {k: headers[k] for k in headers if k.startswith("access-control-")},
        "set_cookie_observed": "set-cookie" in headers,
        "body_snippet": body_text[:500],
    }


def should_focus(endpoint: str):
    lower = endpoint.lower()
    return any(h.lower() in lower for h in FOCUS_ENDPOINT_HINTS)


def allow_empty_get(endpoint: str):
    lower = endpoint.lower()
    if any(h.lower() in lower for h in GET_DENY_HINTS):
        return False
    parsed = urlsplit(endpoint)
    # Avoid sending arbitrary pre-filled secrets or workflow parameters.
    if any(key.lower() in SENSITIVE_QUERY_KEYS for key, _ in parse_qsl(parsed.query, keep_blank_values=True)):
        return False
    return True


def is_public_or_spa_fallback(url: str, body_lower: str):
    if "doesn't work properly without javascript enabled" in body_lower:
        return True
    if "work-phone-admin" in body_lower and "javascript enabled" in body_lower:
        return True
    path = urlsplit(url).path.lower()
    if path.endswith(("/useragreement", "/privacyagreement")):
        return True
    return False


def load_endpoints():
    endpoints = {}
    for line in INPUT.read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        for endpoint in row.get("endpoints") or []:
            url = endpoint["url"]
            if should_focus(url):
                endpoints[url] = {
                    "url": url,
                    "source": row["url"],
                    "labels": endpoint.get("labels") or [],
                    "methods_observed": endpoint.get("methods_observed") or [],
                    "params_observed": endpoint.get("params_observed") or [],
                }
    return sorted(endpoints.values(), key=lambda e: e["url"])


def main():
    if not PROXY_USER:
        raise SystemExit("PENTEST_PROXY_USER is required")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    endpoints = load_endpoints()
    results = []
    for endpoint in endpoints:
        requests = ["OPTIONS"]
        if allow_empty_get(endpoint["url"]):
            requests.append("GET")
        item = {
            "url": redact_url(endpoint["url"]),
            "source": redact_url(endpoint["source"]),
            "labels": endpoint["labels"],
            "static_methods_observed": endpoint["methods_observed"],
            "static_params_observed": endpoint["params_observed"],
            "empty_get_sent": "GET" in requests,
            "results": [],
        }
        for method in requests:
            time.sleep(0.25)
            item["results"].append(curl_request(method, endpoint["url"]))
        results.append(item)
        print(json.dumps(item, ensure_ascii=False), flush=True)

    JSONL.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in results) + "\n")
    status_counts = {}
    unauth_sensitive = []
    cors_credentials = []
    for item in results:
        for res in item["results"]:
            key = f"{res['method']} {res['status'] or 'NO_RESPONSE'}"
            status_counts[key] = status_counts.get(key, 0) + 1
            body_lower = res["body_snippet"].lower()
            if res["method"] == "GET" and any(ok in res["status"] for ok in ["200", "206"]) and not any(deny in body_lower for deny in ["unauthorized", "未登录", "登录", "token", "forbidden"]) and not is_public_or_spa_fallback(item["url"], body_lower):
                if any(label in item["labels"] for label in ["用户资料", "认证/登录", "短信/验证码", "密码找回/修改", "支付/会员"]):
                    unauth_sensitive.append(item["url"])
            ac = res["access_control"]
            if ac.get("access-control-allow-credentials") == ["true"]:
                cors_credentials.append(item["url"])
    summary = {
        "endpoints_tested": len(results),
        "requests_sent": sum(len(r["results"]) for r in results),
        "empty_get_sent": sum(1 for r in results if r["empty_get_sent"]),
        "status_counts": status_counts,
        "potential_unauth_sensitive_get": sorted(set(unauth_sensitive)),
        "cors_credentials_observed": sorted(set(cors_credentials)),
    }
    SUMMARY.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")

    lines = [
        "# API 无参数可达性基线证据",
        "",
        f"时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "代理出口：已确认为 `39.106.140.81`",
        "测试方式：对静态地图中的重点候选接口发送 OPTIONS；仅对低风险接口发送无参数、无 Cookie、无请求体 GET。未发送 POST/PUT/PATCH/DELETE，未传手机号/验证码，未触发短信、支付、上传、导出、密码修改。",
        "",
        "## 汇总",
        "",
        f"- 候选接口：{summary['endpoints_tested']}",
        f"- 总请求数：{summary['requests_sent']}",
        f"- 空 GET 数：{summary['empty_get_sent']}",
        f"- 状态分布：{json.dumps(summary['status_counts'], ensure_ascii=False)}",
        "",
        "## 逐接口结果",
        "",
    ]
    report = [
        "# API 无参数可达性基线报告",
        "",
        "## 测试边界",
        "",
        "- 仅发送 OPTIONS 与少量空 GET。",
        "- 未发送 POST/PUT/PATCH/DELETE，未携带 Cookie，未提交手机号/验证码/账号/密码，未触发短信、支付、会员、上传、导出或密码修改。",
        "",
        "## 结论摘要",
        "",
        f"- 候选接口：{summary['endpoints_tested']}",
        f"- 总请求数：{summary['requests_sent']}",
        f"- 空 GET 数：{summary['empty_get_sent']}",
        f"- 状态分布：{json.dumps(summary['status_counts'], ensure_ascii=False)}",
        "",
    ]
    if summary["potential_unauth_sensitive_get"]:
        report += [
            "## 需人工复核的异常",
            "",
            "以下接口在无 Cookie 空 GET 下返回 200/206，且未在短响应中看到明显未登录/拒绝标识。该项只是观察点，尚不能直接写成漏洞，需要人工复核响应内容是否为敏感数据。",
            "",
        ]
        for url in summary["potential_unauth_sensitive_get"]:
            report.append(f"- `{url}`")
        report.append("")
    else:
        report += ["## 需人工复核的异常", "", "- 本轮未发现可直接支持“未认证敏感接口可访问”的证据。", ""]

    for item in results:
        lines.append(f"### `{item['url']}`")
        lines.append(f"- 来源：`{item['source']}`")
        lines.append(f"- 标签：{', '.join(item['labels']) or '-'}")
        lines.append(f"- 空 GET：{'已发送' if item['empty_get_sent'] else '跳过'}")
        for res in item["results"]:
            lines.append(f"  - {res['method']}：{res['status'] or res['error'] or '无响应'}；Content-Type={res['content_type'] or '-'}；Set-Cookie={'是' if res['set_cookie_observed'] else '否'}；摘要={res['body_snippet'] or '-'}")
        lines.append("")

    report += ["## 下一步建议", "", "- 对 `qyphone` 和 `speedupload` 的短信/验证码、登录、用户资料接口，如需继续验证限流、未授权、重放或验证码逻辑，需要进入带参数的受控测试。", "- 带参数测试应使用用户授权手机号，严格计数，先单接口单次验证，不做爆破。", "", "## 证据索引", "", f"- 证据摘要：`{EVIDENCE}`", f"- 原始 JSONL：`{JSONL}`"]
    EVIDENCE.write_text("\n".join(lines) + "\n")
    REPORT.write_text("\n".join(report) + "\n")
    print(json.dumps(summary, ensure_ascii=False))
    print(f"EVIDENCE={EVIDENCE}")
    print(f"REPORT={REPORT}")


if __name__ == "__main__":
    main()
