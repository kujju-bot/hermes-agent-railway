#!/usr/bin/env python3
"""Cookie-based auth proxy for Hermes dashboard on Railway."""

import hashlib
import hmac
import re
import os
import pathlib
import secrets
import string
import subprocess
import sys
import time
import aiohttp

from aiohttp import web, ClientSession, WSMsgType

HERMES_HOME = "/root/.hermes"
UPSTREAM = "http://127.0.0.1:9119"
WEBUI_UPSTREAM = "http://127.0.0.1:8787"
PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "")
SECRET = secrets.token_bytes(32)
COOKIE = "hermes_auth"
MAX_AGE = 7 * 86400

_STATIC_EXTENSIONS = {
    ".ico", ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".avif",
}

def _is_static_asset(path):
    ext = os.path.splitext(path)[1].lower()
    return ext in _STATIC_EXTENSIONS

if not PASSWORD:
    print("ERROR: DASHBOARD_PASSWORD must be set.", file=sys.stderr)
    sys.exit(1)

# Load templates from files at startup
_TEMPLATE_DIR = pathlib.Path("/templates")
LOGIN_HTML = _TEMPLATE_DIR.read_text("login.html") if False else (_TEMPLATE_DIR / "login.html").read_text()
GATEWAY_WIDGET = (_TEMPLATE_DIR / "gateway_widget.html").read_text()
LOADING_HTML = (_TEMPLATE_DIR / "loading.html").read_text()


def make_token():
    expires = str(int(time.time()) + MAX_AGE)
    sig = hmac.new(SECRET, expires.encode(), hashlib.sha256).hexdigest()
    return f"{expires}.{sig}"


def check_token(token):
    try:
        expires, sig = token.rsplit(".", 1)
        if int(expires) < time.time():
            return False
        expected = hmac.new(SECRET, expires.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected)
    except Exception:
        return False


async def login_page(request):
    error = ""
    if request.query.get("error"):
        error = '<div class="error">Invalid username or password</div>'
    return web.Response(
        text=string.Template(LOGIN_HTML).safe_substitute(error=error),
        content_type="text/html",
    )


async def login_post(request):
    data = await request.post()
    password = data.get("password", "")

    if hmac.compare_digest(password, PASSWORD):
        next_path = _safe_next_path(request.cookies.get("_next")) or "/"
        resp = web.HTTPFound(next_path)
        resp.set_cookie(COOKIE, make_token(), max_age=MAX_AGE, httponly=True, samesite="Lax")
        resp.del_cookie("_next")
        return resp

    raise web.HTTPFound("/login?error=1")


async def logout(request):
    resp = web.HTTPFound("/login")
    resp.del_cookie(COOKIE)
    return resp


def _safe_next_path(path):
    """Validate a redirect target to prevent open redirects."""
    if path and path.startswith("/") and not path.startswith("//") and "\n" not in path and "\r" not in path:
        return path
    return None


@web.middleware
async def auth_middleware(request, handler):
    if request.path in ("/login", "/logout", "/api/health") or request.path.startswith("/webhooks/") or request.path.startswith("/hapi/"):
        return await handler(request)

    token = request.cookies.get(COOKIE)
    if not token or not check_token(token):
        if request.path.startswith("/api/") or _is_static_asset(request.path):
            raise web.HTTPUnauthorized()
        # Remember where the user was trying to go so we can send them back after login.
        # Encode it in a short-lived cookie rather than a query param.
        target = _safe_next_path(request.path_qs)
        resp = web.HTTPFound("/login")
        if target:
            resp.set_cookie("_next", target, max_age=600, httponly=True, samesite="Lax")
        else:
            resp.del_cookie("_next")
        raise resp

    return await handler(request)


gateway_process = None
webhook_proxy_process = None


def start_gateway():
    global gateway_process
    if gateway_process and gateway_process.poll() is None:
        gateway_process.terminate()
        try:
            gateway_process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            gateway_process.kill()
    gateway_process = subprocess.Popen(["hermes", "gateway", "run"])


def start_webhook_proxy():
    global webhook_proxy_process
    if webhook_proxy_process and webhook_proxy_process.poll() is None:
        webhook_proxy_process.terminate()
        try:
            webhook_proxy_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            webhook_proxy_process.kill()
    webhook_proxy_process = subprocess.Popen([
        "python3", "/root/.hermes/scripts/webhook_filter_proxy.py"
    ])


RESTART_PATHS = {
    ("PUT", "/api/config"),
    ("PUT", "/api/env"),
    ("DELETE", "/api/env"),
}


def volume_attached():
    return os.path.ismount(HERMES_HOME)


async def restart_gateway(request):
    start_gateway()
    return web.json_response({"status": "gateway restarted"})


async def gateway_status(request):
    gw_running = gateway_process is not None and gateway_process.poll() is None
    wp_running = webhook_proxy_process is not None and webhook_proxy_process.poll() is None
    return web.json_response({
        "running": gw_running,
        "webhook_proxy_running": wp_running,
        "volume": volume_attached(),
    })


async def health(request):
    return web.json_response({"status": "ok"})


# ---------------------------------------------------------------------------
# Webhook filter proxy forwarding
# ---------------------------------------------------------------------------

WEBHOOK_PROXY_URL = "http://127.0.0.1:8645"
API_SERVER_UPSTREAM = "http://127.0.0.1:8642"
API_SERVER_KEY = os.environ.get("API_SERVER_KEY", "")


async def webhook_proxy(request):
    """Forward webhook requests to the filter proxy on port 8645."""
    raw_body = await request.read()
    headers = {
        "Content-Type": "application/json",
        "X-GitHub-Event": request.headers.get("X-GitHub-Event", ""),
        "X-Hub-Signature-256": request.headers.get("X-Hub-Signature-256", ""),
        "X-GitHub-Delivery": request.headers.get("X-GitHub-Delivery", ""),
    }
    # Preserve original path (e.g. /webhooks/pr-review-comments)
    target_url = f"{WEBHOOK_PROXY_URL}{request.path}"

    try:
        timeout = aiohttp.ClientTimeout(total=30)
        async with ClientSession(timeout=timeout) as session:
            async with session.post(target_url, data=raw_body, headers=headers) as resp:
                body = await resp.read()
                return web.Response(status=resp.status, body=body, content_type="application/json")
    except Exception as e:
        return web.json_response({"error": f"Webhook proxy forward failed: {e}"}, status=502)


# ---------------------------------------------------------------------------
# Generic proxy helpers
# ---------------------------------------------------------------------------

async def _proxy_ws(request, upstream_url):
    """Forward a WebSocket connection to upstream_url."""
    ws_client = web.WebSocketResponse()
    await ws_client.prepare(request)

    async with ClientSession() as session:
        async with session.ws_connect(upstream_url) as ws_upstream:

            async def forward(src, dst):
                async for msg in src:
                    if msg.type == WSMsgType.TEXT:
                        await dst.send_str(msg.data)
                    elif msg.type == WSMsgType.BINARY:
                        await dst.send_bytes(msg.data)
                    elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                        break

            import asyncio
            await asyncio.gather(
                forward(ws_client, ws_upstream),
                forward(ws_upstream, ws_client),
            )

    return ws_client


async def _proxy_http(request, upstream_base, inject_widget=False, restart_check=False):
    """Forward an HTTP request to upstream_base + request path."""
    async with ClientSession() as session:
        url = f"{upstream_base}{request.path_qs}"
        headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "transfer-encoding")}

        body = await request.read()
        try:
            async with session.request(
                request.method,
                url,
                headers=headers,
                data=body,
                allow_redirects=False,
            ) as resp:
                excluded = {"transfer-encoding", "content-encoding", "content-length"}
                proxy_headers = {k: v for k, v in resp.headers.items() if k.lower() not in excluded}
                content = await resp.read()

                if restart_check and (request.method, request.path) in RESTART_PATHS and resp.status < 400:
                    start_gateway()

                content_type = resp.headers.get("content-type", "")
                if "text/html" in content_type:
                    html_headers = {k: v for k, v in proxy_headers.items() if k.lower() != "content-type"}
                    html = content.decode("utf-8", errors="replace")
                    if inject_widget:
                        html = html.replace("</body>", GATEWAY_WIDGET + "</body>")
                    return web.Response(status=resp.status, headers=html_headers, text=html, content_type="text/html")
                return web.Response(status=resp.status, headers=proxy_headers, body=content)
        except aiohttp.ClientConnectorError:
            if "text/html" in request.headers.get("Accept", ""):
                return web.Response(status=503, content_type="text/html", text=LOADING_HTML)
            return web.Response(status=503, text="Service Unavailable: Upstream is down.")


# ---------------------------------------------------------------------------
# Dashboard proxy  (/, /api/*, /assets/*, etc.)
# ---------------------------------------------------------------------------

async def proxy(request):
    # API server proxy: /hapi/v1/* -> API server on :8642
    if request.path.startswith("/hapi/"):
        return await api_server_proxy(request)
    
    if request.headers.get("Upgrade", "").lower() == "websocket":
        url = f"ws://127.0.0.1:9119{request.path_qs}"
        return await _proxy_ws(request, url)
    return await _proxy_http(request, UPSTREAM, inject_widget=True, restart_check=True)


# ---------------------------------------------------------------------------
# WebUI proxy  (/webui, /webui/*)
# ---------------------------------------------------------------------------

def _strip_webui_prefix(path_qs):
    """Strip the /webui prefix so hermes-webui sees paths starting with /."""
    # path_qs includes query string, e.g. /webui/chat?foo=bar
    if path_qs.startswith("/webui"):
        stripped = path_qs[6:]  # remove "/webui"
        if not stripped or stripped.startswith("?"):
            stripped = "/" + stripped
        return stripped
    return path_qs


async def webui_proxy(request):
    upstream_path = _strip_webui_prefix(request.path_qs)

    if request.headers.get("Upgrade", "").lower() == "websocket":
        url = f"ws://127.0.0.1:8787{upstream_path}"
        return await _proxy_ws(request, url)

    async with ClientSession() as session:
        url = f"{WEBUI_UPSTREAM}{upstream_path}"

        # Rewrite headers for the webui backend.
        # We strip Host/transfer-encoding as usual, but also rewrite Origin and Referer
        # because hermes-webui does a CSRF check comparing Origin to its own Host.
        # The browser sends Origin: http://localhost:8080, but webui expects 127.0.0.1:8787.
        skip = {"host", "transfer-encoding"}
        headers = {}
        for k, v in request.headers.items():
            kl = k.lower()
            if kl in skip:
                continue
            if kl == "origin":
                headers[k] = "http://127.0.0.1:8787"
            elif kl == "referer":
                headers[k] = v.replace(str(request.url.origin()), "http://127.0.0.1:8787")
            else:
                headers[k] = v

        body = await request.read()
        async with session.request(
            request.method,
            url,
            headers=headers,
            data=body,
            allow_redirects=False,
        ) as resp:
            content_type = resp.headers.get("content-type", "")

            # SSE / streaming: forward chunk-by-chunk so the browser receives
            # tokens in real-time instead of waiting for the full response.
            if "text/event-stream" in content_type:
                streaming_resp = web.StreamResponse(status=resp.status)
                streaming_resp.content_type = "text/event-stream"
                streaming_resp.headers["Cache-Control"] = "no-cache"
                streaming_resp.headers["X-Accel-Buffering"] = "no"
                streaming_resp.headers["Connection"] = "close"
                excluded = {"transfer-encoding", "content-encoding", "content-length",
                            "content-type", "cache-control", "connection"}
                for k, v in resp.headers.items():
                    if k.lower() not in excluded:
                        streaming_resp.headers[k] = v
                await streaming_resp.prepare(request)
                try:
                    async for chunk in resp.content.iter_any():
                        await streaming_resp.write(chunk)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                    pass
                await streaming_resp.write_eof()
                return streaming_resp

            excluded = {"transfer-encoding", "content-encoding", "content-length"}
            proxy_headers = {k: v for k, v in resp.headers.items() if k.lower() not in excluded}
            content = await resp.read()

            if "text/html" in content_type:
                html_headers = {k: v for k, v in proxy_headers.items() if k.lower() != "content-type"}
                html = content.decode("utf-8", errors="replace")
                # Rewrite absolute asset paths (/foo -> /webui/foo).
                # Negative lookahead (?!/) skips protocol-relative URLs like //cdn.example.com.
                html = re.sub(r'((?:src|href|action)=")(/(?!/))', r'\1/webui\2', html)
                html = re.sub(r"((?:src|href|action)=')(/(?!/))", r"\1/webui\2", html)
                # Also inject <base href> so relative paths (no leading slash) resolve correctly.
                if "<base " not in html:
                    html = html.replace("<head>", '<head>\n<base href="/webui/">', 1)
                return web.Response(status=resp.status, headers=html_headers, text=html, content_type="text/html")
            return web.Response(status=resp.status, headers=proxy_headers, body=content)


# ---------------------------------------------------------------------------
# App wiring
# ---------------------------------------------------------------------------

async def api_server_proxy(request):
    """Proxy /hapi/v1/* to the API server on port 8642.
    
    Auth: requires the dashboard password as a Bearer token in the Authorization header
    (same password used for the dashboard login). The proxy then injects the real
    API_SERVER_KEY when forwarding to the API server.
    """
    # Check auth: client must send "Authorization: Bearer <DASHBOARD_PASSWORD>"
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise web.HTTPUnauthorized(text="Missing or invalid Authorization header")
    
    provided_password = auth_header[7:]  # strip "Bearer "
    if not hmac.compare_digest(provided_password, PASSWORD):
        raise web.HTTPUnauthorized(text="Invalid password")
    
    # Forward to API server with the real API server key
    upstream_path = request.path_qs
    if upstream_path.startswith("/hapi/v1"):
        upstream_path = upstream_path[len("/hapi/v1"):]  # strip /hapi/v1 prefix
    if not upstream_path:
        upstream_path = "/"
    
    url = f"{API_SERVER_UPSTREAM}{upstream_path}"
    headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "transfer-encoding", "authorization")}
    headers["Authorization"] = f"Bearer {API_SERVER_KEY}"
    
    body = await request.read()
    try:
        timeout = aiohttp.ClientTimeout(total=300)
        async with ClientSession(timeout=timeout) as session:
            async with session.request(
                request.method,
                url,
                headers=headers,
                data=body,
                allow_redirects=False,
            ) as resp:
                excluded = {"transfer-encoding", "content-encoding", "content-length"}
                proxy_headers = {k: v for k, v in resp.headers.items() if k.lower() not in excluded}
                content = await resp.read()
                
                content_type = resp.headers.get("content-type", "")
                if "text/event-stream" in content_type:
                    streaming_resp = web.StreamResponse(status=resp.status)
                    streaming_resp.content_type = "text/event-stream"
                    streaming_resp.headers["Cache-Control"] = "no-cache"
                    streaming_resp.headers["X-Accel-Buffering"] = "no"
                    streaming_resp.headers["Connection"] = "close"
                    excluded_h = {"transfer-encoding", "content-encoding", "content-length",
                                  "content-type", "cache-control", "connection"}
                    for k, v in resp.headers.items():
                        if k.lower() not in excluded_h:
                            streaming_resp.headers[k] = v
                    await streaming_resp.prepare(request)
                    try:
                        async for chunk in resp.content.iter_any():
                            await streaming_resp.write(chunk)
                    except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                        pass
                    await streaming_resp.write_eof()
                    return streaming_resp
                
                return web.Response(status=resp.status, headers=proxy_headers, body=content)
    except aiohttp.ClientConnectorError:
        return web.json_response({"error": "API server is unreachable"}, status=502)


async def on_startup(app):
    start_gateway()
    start_webhook_proxy()


def create_app():
    app = web.Application(middlewares=[auth_middleware])
    app.on_startup.append(on_startup)

    # Auth routes
    app.router.add_get("/login", login_page)
    app.router.add_post("/login", login_post)
    app.router.add_get("/logout", logout)

    # Internal API routes handled by the proxy itself
    app.router.add_get("/api/health", health)
    app.router.add_post("/api/gateway/restart", restart_gateway)
    app.router.add_get("/api/gateway/status", gateway_status)

    # WebUI: bare /webui redirects to /webui/ so relative asset paths resolve correctly.
    app.router.add_get("/webui", lambda r: web.HTTPMovedPermanently("/webui/"))
    app.router.add_route("*", "/webui/", webui_proxy)
    app.router.add_route("*", "/webui/{path_info:.*}", webui_proxy)

    # Webhook filter proxy — forwards to filter proxy on port 8645
    app.router.add_route("*", "/webhooks/{path_info:.*}", webhook_proxy)

    # Dashboard catch-all
    app.router.add_route("*", "/{path_info:.*}", proxy)
    return app


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    web.run_app(create_app(), host="0.0.0.0", port=port)
