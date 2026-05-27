#!/usr/bin/env python3
import json
import os
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

OUT_DIR = Path("outputs/controlled_negative_20260527")
JSONL = OUT_DIR / "controlled_negative_results.jsonl"
SUMMARY = OUT_DIR / "summary.json"
EVIDENCE = Path("pentest_state/requests/controlled-negative-validation-20260527.txt")
REPORT = Path("pentest_state/report-controlled-negative-validation-20260527.md")

PROXY_HOST = "39.106.140.81:8877"
PROXY_USER = os.environ.get("PENTEST_PROXY_USER", "")
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36"
SENSITIVE_QUERY_KEYS = {"access_token", "auth", "code", "key", "password", "secret", "session", "sessionid", "sid", "ticket", "token"}

TESTS = [
    {
        "id": "speedupload-captcha-get",
        "url": "https://speedupload.wostore.cn/captcha",
        "method": "GET",
        "body": None,
        "reason": "获取验证码图片/标识，不提交手机号，不触发短信。",
    },
    {
        "id": "speedupload-smscode-empty-post",
        "url": "https://speedupload.wostore.cn/smscodeV2",
        "method": "POST",
        "body": {},
        "reason": "缺少手机号、腾讯验证码 ticket/randstr 的空 JSON，验证是否正确拒绝。",
    },
    {
        "id": "speedupload-login-empty-post",
        "url": "https://speedupload.wostore.cn/login2",
        "method": "POST",
        "body": {},
        "reason": "缺少账号/手机号/验证码/密码的空 JSON，验证是否正确拒绝。",
    },
    {
        "id": "qyphone-pwd-sms-send-empty-post",
        "url": "https://qyphone.wostore.cn:32001/auth/pwd-sms/send",
        "method": "POST",
        "body": {},
        "reason": "缺少手机号、验证码上下文、encrypt-key 的空 JSON，验证是否正确拒绝。",
    },
    {
        "id": "qyphone-baseapi-pwd-sms-send-empty-post",
        "url": "https://qyphone.wostore.cn:32001/base-api/auth/pwd-sms/send",
        "method": "POST",
        "body": {},
        "reason": "补测静态 JS 暴露的 /base-api 网关路径；缺少手机号、验证码上下文、encrypt-key 的空 JSON。",
    },
    {
        "id": "qyphone-pwd-sms-login-empty-post",
        "url": "https://qyphone.wostore.cn:32001/auth/pwd-sms/login",
        "method": "POST",
        "body": {},
        "reason": "缺少手机号、短信验证码、encrypt-key 的空 JSON，验证是否正确拒绝。",
    },
    {
        "id": "qyphone-baseapi-pwd-sms-login-empty-post",
        "url": "https://qyphone.wostore.cn:32001/base-api/auth/pwd-sms/login",
        "method": "POST",
        "body": {},
        "reason": "补测静态 JS 暴露的 /base-api 网关路径；缺少手机号、短信验证码、encrypt-key 的空 JSON。",
    },
    {
        "id": "qyphone-retrieval-send-empty-post",
        "url": "https://qyphone.wostore.cn:32001/user/profile/retrievalPwd/sendSms",
        "method": "POST",
        "body": {},
        "reason": "缺少密码找回身份参数的空 JSON，验证是否正确拒绝。",
    },
    {
        "id": "qyphone-baseapi-retrieval-send-empty-post",
        "url": "https://qyphone.wostore.cn:32001/base-api/system/user/profile/retrievalPwd/sendSms",
        "method": "POST",
        "body": {},
        "reason": "补测静态 JS 暴露的 system 网关路径；缺少密码找回身份参数的空 JSON。",
    },
    {
        "id": "qyphone-retrieval-check-empty-post",
        "url": "https://qyphone.wostore.cn:32001/user/profile/retrievalPwd/check",
        "method": "POST",
        "body": {},
        "reason": "缺少密码找回验证码/身份参数的空 JSON，验证是否正确拒绝。",
    },
    {
        "id": "qyphone-baseapi-retrieval-check-empty-post",
        "url": "https://qyphone.wostore.cn:32001/base-api/system/user/profile/retrievalPwd/check",
        "method": "POST",
        "body": {},
        "reason": "补测静态 JS 暴露的 system 网关路径；缺少密码找回验证码/身份参数的空 JSON。",
    },
    {
        "id": "qyphone-updatepwd-validate-empty-post",
        "url": "https://qyphone.wostore.cn:32001/user/profile/updatePwd/validate",
        "method": "POST",
        "body": {},
        "reason": "缺少修改密码验证参数的空 JSON，验证是否正确拒绝。",
    },
    {
        "id": "qyphone-baseapi-updatepwd-validate-empty-post",
        "url": "https://qyphone.wostore.cn:32001/base-api/system/user/profile/updatePwd/validate",
        "method": "POST",
        "body": {},
        "reason": "补测静态 JS 暴露的 system 网关路径；缺少修改密码验证参数的空 JSON。",
    },
    {
        "id": "member-access-token-empty-code-get",
        "url": "https://member.zlhz.wostore.cn/cxmember/wechat/accessToken?code=",
        "method": "GET",
        "body": None,
        "reason": "仅空 code，不提交真实微信 OAuth code，验证错误处理和 CORS。",
    },
    {
        "id": "member-mobile-login-empty-post",
        "url": "https://member.zlhz.wostore.cn/wcy_member/token/mobile",
        "method": "POST",
        "body": {},
        "reason": "缺少手机号/验证码的空 JSON，验证是否正确拒绝。",
    },
    {
        "id": "member-mobile-login-empty-get",
        "url": "https://member.zlhz.wostore.cn/wcy_member/token/mobile",
        "method": "GET",
        "body": None,
        "reason": "POST 被拒绝且 Allow=GET 后，补测无手机号/验证码 GET 是否正确拒绝。",
    },
    {
        "id": "member-send-valid-code-empty-post",
        "url": "https://member.zlhz.wostore.cn/wcy_member/sendMobileValidPictureCode",
        "method": "POST",
        "body": {},
        "reason": "缺少手机号、图片验证码、腾讯验证码的空 JSON，验证是否正确拒绝。",
    },
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


def clean_body(body: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body[:2000])).strip()[:800]


def request(test):
    cmd = [
        "curl", "-sS", "-k",
        "--max-redirs", "0",
        "--connect-timeout", "6",
        "--max-time", "12",
        "--socks5-hostname", PROXY_HOST,
        "--proxy-user", PROXY_USER,
        "-A", UA,
        "-X", test["method"],
        "-H", "Accept: application/json,text/plain,*/*",
        "-H", "Origin: https://audit.invalid",
        "-D", "-",
        "--range", "0-8191",
    ]
    if test["body"] is not None:
        cmd += ["-H", "Content-Type: application/json", "--data-binary", json.dumps(test["body"], ensure_ascii=False)]
    cmd.append(test["url"])
    start = time.time()
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout = decode(p.stdout)
    statuses, headers = parse_headers(stdout)
    body = extract_body(stdout)
    return {
        "id": test["id"],
        "url": redact_url(test["url"]),
        "method": test["method"],
        "reason": test["reason"],
        "body_sent_shape": "empty-json" if test["body"] == {} else "none",
        "exit": p.returncode,
        "elapsed_sec": round(time.time() - start, 2),
        "error": decode(p.stderr).strip()[:240],
        "status": statuses[-1] if statuses else "",
        "content_type": (headers.get("content-type") or [""])[0],
        "set_cookie_observed": "set-cookie" in headers,
        "interesting_headers": {
            k: v for k, v in headers.items()
            if k in {"allow", "capt_id"} or k.startswith("access-control-")
        },
        "body_snippet": clean_body(body),
    }


def classify(result):
    text = f"{result['status']} {result['body_snippet']}".lower()
    if not result["status"]:
        return "无响应/无法验证"
    if any(code in result["status"] for code in ["400", "401", "403", "404", "405", "415", "422"]) or any(word in text for word in ["缺少", "不能为空", "invalid", "error", "失败", "参数", "错误", "\"code\":\"9001\"", "\"code\":\"9898\"", "\"code\": 401", "\"code\":401", "missing code", "无权限访问", "未能读取到有效 token"]):
        return "正确拒绝/需要参数"
    if any(code in result["status"] for code in ["200", "206"]) and result["method"] == "POST":
        return "需复核：空 POST 返回成功类状态"
    if any(code in result["status"] for code in ["200", "206"]) and result["method"] == "GET":
        return "GET 可访问/需按内容判断"
    return "其他"


def main():
    if not PROXY_USER:
        raise SystemExit("PENTEST_PROXY_USER is required")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    results = []
    for test in TESTS:
        time.sleep(0.5)
        item = request(test)
        item["classification"] = classify(item)
        results.append(item)
        print(json.dumps(item, ensure_ascii=False), flush=True)
    JSONL.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in results) + "\n")
    summary = {
        "tests": len(results),
        "post_requests": sum(1 for r in results if r["method"] == "POST"),
        "get_requests": sum(1 for r in results if r["method"] == "GET"),
        "classification_counts": {},
        "needs_review": [r["url"] for r in results if r["classification"].startswith("需复核")],
    }
    for r in results:
        summary["classification_counts"][r["classification"]] = summary["classification_counts"].get(r["classification"], 0) + 1
    SUMMARY.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")

    lines = [
        "# 受控负向参数验证证据",
        "",
        f"时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "代理出口：已确认为 `39.106.140.81`",
        "测试方式：单接口一次性缺参/空 JSON/空 code 验证；未提交手机号、验证码、账号、密码、真实 OAuth code；未触发短信、支付、会员、上传、导出或密码修改。",
        "",
        "## 汇总",
        "",
        f"- 测试项：{summary['tests']}",
        f"- POST 请求：{summary['post_requests']}",
        f"- GET 请求：{summary['get_requests']}",
        f"- 分类：{json.dumps(summary['classification_counts'], ensure_ascii=False)}",
        "",
        "## 逐项结果",
        "",
    ]
    report = [
        "# 受控负向参数验证报告",
        "",
        "## 测试边界",
        "",
        "- 本轮只做单接口一次性缺参/空 JSON/空 code 验证。",
        "- 未提交手机号、验证码、账号、密码、真实微信 OAuth code。",
        "- 未触发短信、支付、会员、上传、导出或密码修改。",
        "",
        "## 结论摘要",
        "",
        f"- 测试项：{summary['tests']}",
        f"- 分类：{json.dumps(summary['classification_counts'], ensure_ascii=False)}",
        "",
    ]
    if summary["needs_review"]:
        report += ["## 需复核项", ""]
        for url in summary["needs_review"]:
            report.append(f"- `{url}`")
        report.append("")
    else:
        report += ["## 需复核项", "", "- 本轮未发现空 POST 返回成功类状态的接口。", ""]

    for r in results:
        lines.append(f"### `{r['id']}`")
        lines.append(f"- URL：`{r['url']}`")
        lines.append(f"- 方法：{r['method']}；请求体：{r['body_sent_shape']}")
        lines.append(f"- 目的：{r['reason']}")
        lines.append(f"- 响应：{r['status'] or r['error'] or '无响应'}")
        lines.append(f"- 分类：{r['classification']}")
        lines.append(f"- 响应摘要：{r['body_snippet'] or '-'}")
        lines.append(f"- 关键响应头：{json.dumps(r['interesting_headers'], ensure_ascii=False) if r['interesting_headers'] else '-'}")
        lines.append("")

        report.append(f"## `{r['id']}`")
        report.append("")
        report.append(f"- URL：`{r['url']}`")
        report.append(f"- 方法：{r['method']}；请求体：{r['body_sent_shape']}")
        report.append(f"- 响应：{r['status'] or r['error'] or '无响应'}")
        report.append(f"- 结论：{r['classification']}")
        report.append(f"- 论据：{r['body_snippet'] or '无响应体摘要'}")
        report.append("")

    report += ["## 证据索引", "", f"- 证据摘要：`{EVIDENCE}`", f"- 原始 JSONL：`{JSONL}`"]
    EVIDENCE.write_text("\n".join(lines) + "\n")
    REPORT.write_text("\n".join(report) + "\n")
    print(json.dumps(summary, ensure_ascii=False))
    print(f"EVIDENCE={EVIDENCE}")
    print(f"REPORT={REPORT}")


if __name__ == "__main__":
    main()
