#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pixiv-token —— 在本机获取 Pixiv refresh_token 的小工具

纯标准库实现，零依赖。运行后在浏览器里按提示登录，粘贴回调地址，
即可拿到 refresh_token 并保存到本地 JSON。

用法:
    python pixiv_token.py
    python pixiv_token.py --proxy http://127.0.0.1:7890
    python pixiv_token.py --port 18000 --no-browser
"""

import argparse
import base64
import hashlib
import http.server
import json
import os
import re
import secrets
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

__version__ = "1.1.0"

# ---------------------------------------------------------------------------
# Pixiv Android 客户端参数（App 内置的公开参数，不是你的账号密码）
# 旧值 MOBrBDS8blbauoSck0Zf 已被 Pixiv 淘汰，会返回 403「不正なOAuthクライアントです」
# ---------------------------------------------------------------------------
CLIENT_ID = "MOBrBDS8blbauoSck0ZfDbtuzpyT"
CLIENT_SECRET = "lsACyCD94FhDUtGTXi3QzcFE2uU1hqtDaKeqrdwj"
REDIRECT_URI = "https://app-api.pixiv.net/web/v1/users/auth/pixiv/callback"
LOGIN_URL = (
    "https://app-api.pixiv.net/web/v1/login"
    "?code_challenge={challenge}&code_challenge_method=S256&client=pixiv-android"
)
TOKEN_URL = "https://oauth.secure.pixiv.net/auth/token"
UA = "PixivAndroidApp/5.0.234 (Android 11; Pixel 5)"

DEFAULT_PORT = 17777
HERE = os.path.dirname(os.path.abspath(__file__))
RESULT_FILE = os.path.join(HERE, "pixiv_token.json")

# 本地常见代理端口，按顺序探测（Clash / v2rayN / sing-box 等）
PROXY_PORTS = (7890, 7897, 7891, 1080, 10809, 2080, 8889)

CODE_RE = re.compile(r"[?&#]code=([^&#\s]+)")

STATE = {"verifier": "", "challenge": "", "proxy": ""}
LOCK = threading.Lock()

_opener = None
_active_proxy = None


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------
def setup_console():
    """Windows 控制台默认不是 UTF-8，避免打印日文报错时崩掉。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def env_proxy():
    for key in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
                "ALL_PROXY", "all_proxy"):
        val = os.environ.get(key)
        if val:
            return val
    return ""


def detect_proxy():
    """优先级：环境变量 > 本地常见代理端口 > 直连（探测结果会再做一次可用性校验）。"""
    val = env_proxy()
    if val:
        return val
    for port in PROXY_PORTS:
        try:
            probe = socket.create_connection(("127.0.0.1", port), timeout=0.4)
            probe.close()
        except OSError:
            continue
        candidate = f"http://127.0.0.1:{port}"
        if proxy_works(candidate):
            return candidate
    return ""


def proxy_works(proxy, host="oauth.secure.pixiv.net", port=443, timeout=4.0):
    """用 CONNECT 握手验证探测到的代理是否真的能出网，避免把随便开着的端口当代理。"""
    if not proxy:
        return False
    parsed = urllib.parse.urlparse(proxy)
    if parsed.scheme not in ("", "http", "https"):
        return True  # socks 之类无法这样验证，直接交给 urllib
    try:
        sock = socket.create_connection(
            (parsed.hostname or "127.0.0.1", parsed.port or 8080), timeout=timeout)
    except OSError:
        return False
    try:
        sock.sendall(
            f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
        sock.settimeout(timeout)
        head = sock.recv(64)
        return head.startswith(b"HTTP/1.") and b" 200" in head
    except OSError:
        return False
    finally:
        try:
            sock.close()
        except OSError:
            pass


def get_opener(proxy):
    global _opener, _active_proxy
    if _opener is not None and _active_proxy == proxy:
        return _opener
    if proxy:
        handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
    else:
        handler = urllib.request.ProxyHandler({})
    _opener = urllib.request.build_opener(handler)
    _active_proxy = proxy
    return _opener


def new_pkce():
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    with LOCK:
        STATE["verifier"] = verifier
        STATE["challenge"] = challenge
    return challenge


def extract_code(text):
    """从粘贴内容里找出 code，兼容 pixiv:// 地址、callback 地址和裸 code。"""
    text = (text or "").strip()
    if not text:
        return None
    candidates = [text]
    cur = text
    for _ in range(3):  # 允许嵌套编码（比如整条 URL 被 encode 过）
        nxt = urllib.parse.unquote(cur)
        if nxt == cur:
            break
        cur = nxt
        candidates.append(cur)
    for candidate in candidates:
        match = CODE_RE.search(candidate)
        if match:
            return urllib.parse.unquote(match.group(1))
    if re.fullmatch(r"[A-Za-z0-9_\-~.%=]+", text) and len(text) > 8:
        return urllib.parse.unquote(text)
    return None


def friendly_error(status, body):
    """把 Pixiv 的日文报错翻译成人能看懂的原因。"""
    if "OAuth" in body and status == 403:
        return ("Pixiv 认为客户端参数无效（不正なOAuthクライアントです）。"
                "通常是 client_id 过期，请更新脚本里的 CLIENT_ID。")
    if status == 400 or status == 403:
        return ("code 无效或已过期（有效期只有几十秒），也可能与当前登录会话不匹配。"
                "请返回本地页面重新点一次登录，拿到新的 callback 地址后立刻粘贴。")
    return f"Pixiv 返回 HTTP {status}: {body[:300]}"


def exchange_token(code):
    payload = urllib.parse.urlencode({
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "code_verifier": STATE["verifier"],
        "grant_type": "authorization_code",
        "redirect_uri": REDIRECT_URI,
        "include_policy": "true",
    }).encode()
    req = urllib.request.Request(
        TOKEN_URL,
        data=payload,
        headers={
            "User-Agent": UA,
            "App-OS": "android",
            "App-OS-Version": "11",
            "App-Version": "5.0.234",
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": "https://app-api.pixiv.net/",
        },
    )
    opener = get_opener(STATE.get("proxy", ""))
    try:
        with opener.open(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        raise RuntimeError(friendly_error(exc.code, body)) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"连不上 Pixiv（{exc.reason}）。请确认代理/加速器已开启，"
            "或用 --proxy http://127.0.0.1:端口 指定代理后重试。"
        ) from exc


def save_result(record):
    try:
        with open(RESULT_FILE, "w", encoding="utf-8") as fh:
            json.dump(record, fh, ensure_ascii=False, indent=2)
        os.chmod(RESULT_FILE, 0o600)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# 本地页面
# ---------------------------------------------------------------------------
PAGE = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pixiv Refresh Token 获取</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { font-family: "Segoe UI","Microsoft YaHei",system-ui,sans-serif; max-width: 760px;
         margin: 0 auto; padding: 28px 18px 60px; line-height: 1.65; }
  h1 { font-size: 22px; margin: 0 0 4px; }
  .sub { opacity: .65; font-size: 13px; margin-bottom: 22px; }
  .card { border: 1px solid rgba(128,128,128,.35); border-radius: 12px; padding: 18px 20px; margin-bottom: 16px; }
  .step { font-size: 13px; font-weight: 700; letter-spacing: .04em; opacity: .75; margin-bottom: 8px; }
  a.btn, button { display: inline-block; border: 0; border-radius: 9px; padding: 11px 18px;
       font-size: 15px; font-weight: 600; cursor: pointer; text-decoration: none;
       background: #0096fa; color: #fff; }
  a.btn:hover, button:hover { filter: brightness(1.08); }
  button:disabled { opacity: .5; cursor: default; }
  textarea { width: 100%; min-height: 84px; margin-top: 10px; padding: 10px 12px; border-radius: 9px;
       border: 1px solid rgba(128,128,128,.45); font: 13px/1.5 Consolas,monospace; resize: vertical;
       background: transparent; color: inherit; }
  code { background: rgba(128,128,128,.18); padding: 1px 5px; border-radius: 4px; font-size: 13px; }
  .msg { margin-top: 12px; font-size: 14px; white-space: pre-wrap; word-break: break-all; }
  .err { color: #e5484d; }
  .ok { color: #12a150; }
  .token { font: 13px/1.6 Consolas,monospace; word-break: break-all; background: rgba(128,128,128,.14);
           padding: 12px 14px; border-radius: 8px; margin-top: 10px; }
  .hint { font-size: 13px; opacity: .7; }
  .row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin-top: 12px; }
</style>
</head>
<body>
<h1>Pixiv Refresh Token 获取</h1>
<div class="sub">全部在本机完成，code 只会发给 Pixiv 官方接口。</div>

<div class="card">
  <div class="step">第 1 步 · 登录 Pixiv</div>
  <p class="hint">用你的 Pixiv 账号登录（需要能正常访问 pixiv）。如果浏览器已登录过，可能直接跳转。</p>
  <div class="row">
    <a class="btn" id="loginLink" href="__LOGIN_URL__" target="_blank" rel="noopener">打开 Pixiv 登录页</a>
    <button id="regen" type="button" style="background:#6b7280">换一个登录链接</button>
  </div>
  <p class="hint" style="margin-top:14px"><b>登录后会发生什么：</b>浏览器会自动跳到
  <code>https://app-api.pixiv.net/web/v1/users/auth/pixiv/callback?state=...&amp;code=...</code>，
  这是一个空白页（或尝试唤起 pixiv:// 应用），这正是我们要的地址。</p>
  <p class="hint"><b>注意：</b>如果你看到的是 <code>accounts.pixiv.net/post-redirect?...</code> 这类页面，
  说明还没跳到终点，<b>不要复制它</b>（里面没有 code）。用开发者工具抓真正的回调请求：</p>
  <ol class="hint" style="padding-left:22px;margin:6px 0 0">
    <li>在 Pixiv 登录页按 <code>F12</code> → <b>Network / 网络</b> 面板</li>
    <li>勾选 <b>Preserve log / 保留日志</b>，过滤框输入 <code>callback</code></li>
    <li>完成登录</li>
    <li>右键那条 <code>.../auth/pixiv/callback?state=...&amp;code=...</code> 请求 →
        Copy → Copy link address</li>
  </ol>
</div>

<div class="card">
  <div class="step">第 2 步 · 粘贴回调地址</div>
  <p class="hint">把上一步的完整地址粘贴到这里。也可以只粘贴 <code>code=</code> 后面那串字符。
  <b>code 有效期只有几十秒</b>，请立刻粘贴。</p>
  <textarea id="cb" placeholder="https://app-api.pixiv.net/web/v1/users/auth/pixiv/callback?state=...&amp;code=..."></textarea>
  <div class="row">
    <button id="go" type="button">换取 Refresh Token</button>
    <span class="hint" id="tip"></span>
  </div>
  <div class="msg" id="msg"></div>
</div>

<div class="card" id="resultCard" style="display:none">
  <div class="step">Refresh Token（等同于账号凭证，请妥善保存）</div>
  <div class="token" id="token"></div>
  <div class="row">
    <button id="copy" type="button">复制 Refresh Token</button>
    <span class="hint" id="copyTip"></span>
  </div>
  <div class="msg" id="meta"></div>
</div>

<script>
const $ = id => document.getElementById(id);
$('regen').addEventListener('click', async () => {
  const r = await fetch('/api/regen', {method: 'POST'});
  const j = await r.json();
  $('loginLink').href = j.login_url;
  $('msg').textContent = '';
  $('msg').className = 'msg';
  $('resultCard').style.display = 'none';
  $('tip').textContent = '登录链接已更新，请重新登录';
});
$('copy').addEventListener('click', async () => {
  const t = $('token').textContent.trim();
  try { await navigator.clipboard.writeText(t); $('copyTip').textContent = '已复制'; }
  catch (e) {
    const ta = document.createElement('textarea');
    ta.value = t; document.body.appendChild(ta); ta.select();
    document.execCommand('copy'); ta.remove(); $('copyTip').textContent = '已复制';
  }
});
$('go').addEventListener('click', async () => {
  const url = $('cb').value.trim();
  if (!url) { $('msg').textContent = '请先粘贴回调地址'; $('msg').className = 'msg err'; return; }
  $('go').disabled = true;
  $('msg').textContent = '正在向 Pixiv 换取 token...';
  $('msg').className = 'msg';
  try {
    const r = await fetch('/api/exchange', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url})
    });
    const j = await r.json();
    if (!j.ok) throw new Error(j.error || '未知错误');
    $('msg').textContent = '成功！token 已保存到 pixiv_token.json';
    $('msg').className = 'msg ok';
    $('token').textContent = j.refresh_token;
    $('meta').textContent = '账号: ' + (j.user_name || '-')
      + (j.user_account ? ' (@' + j.user_account + ')' : '')
      + '\naccess_token 有效期: ' + j.expires_in + ' 秒';
    $('resultCard').style.display = '';
    try { await navigator.clipboard.writeText(j.refresh_token); $('copyTip').textContent = '已自动复制'; }
    catch (e) {}
  } catch (e) {
    $('msg').textContent = '失败: ' + e.message;
    $('msg').className = 'msg err';
  } finally {
    $('go').disabled = false;
  }
});
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# HTTP 服务
# ---------------------------------------------------------------------------
class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "pixiv-token/" + __version__

    def log_message(self, fmt, *args):  # 不输出访问日志
        return

    def _is_local_host(self):
        """只接受来自 127.0.0.1 / localhost 的请求，防止被网页跨站调用。"""
        host = self.headers.get("Host", "")
        if host.startswith("["):
            host = host[1:].split("]")[0]
        else:
            host = host.split(":")[0]
        return host.strip().lower() in ("127.0.0.1", "localhost", "::1")

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False),
                   "application/json; charset=utf-8")

    def do_GET(self):
        if not self._is_local_host():
            self._send(403, "forbidden")
            return
        if self.path in ("/", "/index.html"):
            with LOCK:
                login_url = LOGIN_URL.format(challenge=STATE["challenge"])
            self._send(200, PAGE.replace("__LOGIN_URL__", login_url))
        elif self.path == "/favicon.ico":
            self._send(204, b"")
        else:
            self._send(404, "not found")

    def do_POST(self):
        if not self._is_local_host():
            self._send(403, "forbidden")
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            data = json.loads(self.rfile.read(length).decode("utf-8") or "{}") if length else {}
        except (ValueError, OSError):
            data = {}

        if self.path == "/api/regen":
            challenge = new_pkce()
            self._json({"ok": True,
                        "login_url": LOGIN_URL.format(challenge=challenge)})
            return

        if self.path == "/api/exchange":
            code = extract_code(data.get("url", ""))
            if not code:
                self._json({"ok": False,
                            "error": "没找到 code。请粘贴 callback 地址（或 pixiv:// 地址）。"})
                return
            try:
                resp = exchange_token(code)
            except Exception as exc:  # noqa: BLE001
                self._json({"ok": False, "error": str(exc)})
                return
            refresh_token = resp.get("refresh_token")
            if not refresh_token:
                self._json({"ok": False,
                            "error": "Pixiv 没有返回 refresh_token: "
                                     + json.dumps(resp, ensure_ascii=False)[:300]})
                return
            user = resp.get("user") or {}
            save_result({
                "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "refresh_token": refresh_token,
                "access_token": resp.get("access_token"),
                "expires_in": resp.get("expires_in"),
                "user_id": user.get("id"),
                "user_name": user.get("name"),
                "user_account": user.get("account"),
            })
            print("\n[OK] refresh_token =", refresh_token, flush=True)
            print("[OK] 已保存到", RESULT_FILE, flush=True)
            self._json({
                "ok": True,
                "refresh_token": refresh_token,
                "expires_in": resp.get("expires_in"),
                "user_name": user.get("name"),
                "user_account": user.get("account"),
                "user_id": user.get("id"),
            })
            return

        self._send(404, "not found")


def serve(port, proxy, open_browser=True):
    for _ in range(20):
        try:
            httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
            break
        except OSError:
            port += 1
    else:
        print("找不到可用端口", file=sys.stderr)
        return 1

    url = f"http://127.0.0.1:{port}/"
    print("=" * 62)
    print(" 用浏览器打开下面的地址，按页面提示操作：")
    print("   " + url)
    print(" 访问 Pixiv 使用的代理：", proxy or "直连")
    print(" 成功后的 refresh_token 会显示在页面上，并保存到：")
    print("   " + RESULT_FILE)
    print(" 停止服务：在此窗口按 Ctrl+C")
    print("=" * 62)

    if open_browser:
        threading.Thread(
            target=lambda: (time.sleep(0.6), webbrowser.open(url)), daemon=True
        ).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n已退出。")
    finally:
        httpd.server_close()
    return 0


def main():
    setup_console()
    parser = argparse.ArgumentParser(
        description="获取 Pixiv refresh_token（本机网页版，零依赖）")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"本地监听端口，默认 {DEFAULT_PORT}，被占用时自动 +1")
    parser.add_argument("--proxy", default=None,
                        help="HTTP 代理，如 http://127.0.0.1:7890；direct 表示强制直连")
    parser.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    parser.add_argument("--version", action="version", version="pixiv-token " + __version__)
    args = parser.parse_args()

    if args.proxy is not None:
        proxy = "" if args.proxy.lower() in ("direct", "none", "") else args.proxy
    else:
        proxy = detect_proxy()
    STATE["proxy"] = proxy

    new_pkce()
    sys.exit(serve(args.port, proxy, open_browser=not args.no_browser))


if __name__ == "__main__":
    main()
