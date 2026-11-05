import argparse
import asyncio
import html
import json
import logging
import re
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit

import uvicorn
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool

from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from auth import AuthError, AuthStore, SCOPES, TOOL_SCOPES, parse_scopes, scope_text, verify_password
from events import Events, EventsError


BODY_LIMIT = 65536
VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
COOKIE = "__Host-hermes_oauth_csrf"
SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    "Strict-Transport-Security": "max-age=31536000",
}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate field")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError("Invalid JSON number")


def json_loads(value):
    result = json.loads(value, object_pairs_hook=unique_object, parse_constant=reject_constant)
    json.dumps(result, ensure_ascii=False, allow_nan=False).encode("utf-8")
    return result


def parameters(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AuthError("invalid_request")
        result[key] = value
    return result


def query_parameters(request):
    try:
        raw = request.scope.get("query_string", b"")
        if len(raw) > BODY_LIMIT:
            raise AuthError("invalid_request")
        return parameters(parse_qsl(raw.decode("utf-8"), keep_blank_values=True, max_num_fields=32, errors="strict"))
    except (UnicodeError, ValueError) as exc:
        raise AuthError("invalid_request") from exc


async def form_parameters(request):
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/x-www-form-urlencoded":
        raise AuthError("invalid_request", 415)
    try:
        body = (await request.body()).decode("utf-8")
        return parameters(parse_qsl(body, keep_blank_values=True, max_num_fields=32, errors="strict"))
    except (UnicodeError, ValueError) as exc:
        raise AuthError("invalid_request") from exc


async def json_body(request):
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise AuthError("invalid_request", 415)
    try:
        return json_loads(await request.body())
    except (UnicodeError, ValueError, RecursionError, OverflowError) as exc:
        raise AuthError("invalid_request") from exc


def challenge(auth, error="invalid_token", scopes=None):
    value = f'Bearer resource_metadata="{auth.base_url}/.well-known/oauth-protected-resource/mcp", error="{error}"'
    if scopes:
        value += f', scope="{scope_text(scopes)}"'
    return value


def oauth_error(error):
    return JSONResponse({"error": error.error}, status_code=error.status)


def rpc_result(identifier, result, status=200, headers=None):
    return JSONResponse({"jsonrpc": "2.0", "id": identifier, "result": result}, status_code=status, headers=headers)


def rpc_error(identifier, code, message, status=200, data=None):
    error = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return JSONResponse({"jsonrpc": "2.0", "id": identifier, "error": error}, status_code=status)


class SecurityBoundary:
    def __init__(self, app, auth, port):
        self.app = app
        self.auth = auth
        self.hosts = {urlsplit(auth.base_url).netloc.lower(), f"127.0.0.1:{port}"}
        self.origins = {auth.base_url, "https://chatgpt.com"}

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = False

        async def safe_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                headers = list(message.get("headers", []))
                supplied = {key.lower() for key, value in headers}
                for key, value in SECURITY_HEADERS.items():
                    if key.lower().encode("ascii") not in supplied:
                        headers.append((key.lower().encode("ascii"), value.encode("ascii")))
                message = {**message, "headers": headers}
            await send(message)

        async def respond(response):
            await response(scope, receive, safe_send)

        try:
            headers = {}
            for key, value in scope.get("headers", []):
                key = key.lower()
                if key in (b"host", b"authorization", b"content-length", b"content-type", b"origin", b"mcp-protocol-version") and key in headers:
                    await respond(JSONResponse({"error": "invalid_request"}, status_code=400))
                    return
                headers[key] = value
            if headers.get(b"host", b"").decode("latin-1").lower() not in self.hosts:
                await respond(JSONResponse({"error": "invalid_host"}, status_code=400))
                return
            origin = headers.get(b"origin")
            if origin is not None and origin.decode("latin-1") not in self.origins:
                await respond(JSONResponse({"error": "invalid_origin"}, status_code=403))
                return
            if len(scope.get("query_string", b"")) > BODY_LIMIT:
                await respond(JSONResponse({"error": "request_too_large"}, status_code=414))
                return
            if scope["path"] in ("/mcp", "/mcp/"):
                authorization = headers.get(b"authorization", b"").decode("latin-1")
                match = re.fullmatch(r"Bearer ([A-Za-z0-9_-]{32,256})", authorization, flags=re.IGNORECASE)
                if match is None:
                    await respond(JSONResponse(
                        {"error": "invalid_token"}, status_code=401,
                        headers={"WWW-Authenticate": challenge(self.auth)},
                    ))
                    return
                try:
                    scope["principal"] = await run_in_threadpool(self.auth.authenticate, match.group(1))
                except AuthError:
                    await respond(JSONResponse(
                        {"error": "invalid_token"}, status_code=401,
                        headers={"WWW-Authenticate": challenge(self.auth)},
                    ))
                    return
                if scope.get("query_string"):
                    await respond(JSONResponse({"error": "invalid_request"}, status_code=400))
                    return
            length = headers.get(b"content-length")
            if length is not None:
                if not re.fullmatch(rb"[0-9]{1,10}", length):
                    await respond(JSONResponse({"error": "invalid_request"}, status_code=400))
                    return
                if int(length) > BODY_LIMIT:
                    await respond(JSONResponse({"error": "request_too_large"}, status_code=413))
                    return
            chunks = []
            size = 0
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                if message["type"] != "http.request":
                    continue
                data = message.get("body", b"")
                size += len(data)
                if size > BODY_LIMIT:
                    await respond(JSONResponse({"error": "request_too_large"}, status_code=413))
                    return
                chunks.append(data)
                if not message.get("more_body", False):
                    break
            body = b"".join(chunks)
            delivered = False

            async def bounded_receive():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": body, "more_body": False}
                return await receive()

            await self.app(scope, bounded_receive, safe_send)
        except AuthError as exc:
            if not started:
                await respond(oauth_error(exc))
        except Exception:
            if not started:
                await respond(JSONResponse({"error": "server_error"}, status_code=500))


class Service:
    def __init__(self, settings, backend, events=None):
        self.auth = AuthStore(settings)
        self.backend = backend
        self.events = events
        if events is None and "events" in settings:
            event_settings = settings["events"]
            if not isinstance(event_settings, dict):
                raise ValueError("events settings must be an object")
            event_settings = {**event_settings, "auth_db_path": settings["db_path"]}
            self.events = Events(event_settings, backend, self.auth.grant_active)
        self.capacity = asyncio.Semaphore(16)
        self.timeout = settings.get("backend_timeout_seconds", 60)
        if type(self.timeout) not in (int, float) or not 1 <= self.timeout <= 300:
            raise ValueError("backend_timeout_seconds must be between 1 and 300")
        raw_tools = backend.tools
        if not isinstance(raw_tools, list):
            raise ValueError("Backend tools must be a list")
        self.tools = {}
        for tool in raw_tools:
            if (
                not isinstance(tool, dict)
                or not isinstance(tool.get("name"), str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", tool["name"])
                or tool["name"] in self.tools
                or not isinstance(tool.get("inputSchema"), dict)
                or not isinstance(tool.get("_meta"), dict)
            ):
                raise ValueError("Invalid backend tool definition")
            required = tool["_meta"].get("requiredScopes")
            if (
                not isinstance(required, list) or not required
                or any(not isinstance(item, str) or item not in TOOL_SCOPES for item in required)
            ):
                raise ValueError("Every tool must declare hermes.read, hermes.write or hermes.control in _meta.requiredScopes")
            definition = json_loads(json.dumps(tool, allow_nan=False))
            definition["securitySchemes"] = [{"type": "oauth2", "scopes": sorted(set(required))}]
            definition["_meta"]["securitySchemes"] = definition["securitySchemes"]
            self.tools[tool["name"]] = definition

    def rate_limit(self, request, category):
        address = request.client.host if request.client else "unknown"
        limits = {
            "login": (10, 30, 300),
            "register": (10, 30, 60),
            "authorize": (30, 60, 60),
            "token": (60, 120, 60),
        }
        if not self.auth.limiter.allow(category, address, *limits[category]):
            raise AuthError("temporarily_unavailable", 429)

    async def health(self, request):
        return JSONResponse({"status": "ok"})

    async def resource_metadata(self, request):
        return JSONResponse({
            "resource": self.auth.resource,
            "authorization_servers": [self.auth.base_url],
            "scopes_supported": sorted(SCOPES),
            "bearer_methods_supported": ["header"],
        })

    async def authorization_metadata(self, request):
        base = self.auth.base_url
        return JSONResponse({
            "issuer": base,
            "authorization_endpoint": base + "/authorize",
            "token_endpoint": base + "/token",
            "registration_endpoint": base + "/register",
            "revocation_endpoint": base + "/revoke",
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["none"],
            "revocation_endpoint_auth_methods_supported": ["none"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": sorted(SCOPES),
            "authorization_response_iss_parameter_supported": True,
            "client_id_metadata_document_supported": False,
        })

    async def register(self, request):
        try:
            self.rate_limit(request, "register")
            data = await json_body(request)
            return JSONResponse(await run_in_threadpool(self.auth.register, data), status_code=201)
        except AuthError as exc:
            return oauth_error(exc)

    def login_form(self, authorization, nonce, error=False):
        labels = {
            "hermes.read": "Read your Hermes Telegram topics, conversations and task progress",
            "hermes.write": "Send tasks to Hermes and create or update its topics",
            "hermes.control": "Steer and stop tasks in your Hermes topics",
            "offline_access": "Keep this connection authorized using refresh tokens for up to 30 days",
        }
        requested = parse_scopes(authorization["scope"])
        choices = "".join(
            f'<p><label><input type="checkbox" name="scope_{name}" value="yes" checked> {html.escape(labels[name])}</label></p>'
            for name in ("hermes.read", "hermes.write", "hermes.control", "offline_access") if name in requested
        )
        problem = "<p>Authorization failed. Check the password and permissions.</p>" if error else ""
        body = (
            '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" '
            'content="width=device-width, initial-scale=1"><title>Authorize owner account</title></head><body>'
            '<h1>Authorize ChatGPT</h1><p>This is an owner-only account. Continue only if you own this server.</p>'
            f'<p>Registered client: {html.escape(authorization["client_id"])}</p>'
            f'<p>Callback: {html.escape(authorization["redirect_uri"])}</p>'
            f'<p>Resource: {html.escape(self.auth.resource)}</p>'
            '<p>Read, write and control permissions are independent. Grant only the requested permissions you want.</p>'
            f'{problem}<form method="post" action="/authorize">'
            f'<input type="hidden" name="csrf_nonce" value="{html.escape(nonce, quote=True)}">'
            '<p><label>Owner password <input type="password" name="password" autocomplete="current-password" '
            'maxlength="1024" required></label></p>'
            f'{choices}<button type="submit" name="decision" value="allow">Authorize selected permissions</button> '
            '<button type="submit" name="decision" value="deny" formnovalidate>Deny</button>'
            '</form></body></html>'
        )
        response = HTMLResponse(body, status_code=401 if error else 200)
        response.set_cookie(COOKIE, nonce, max_age=600, secure=True, httponly=True, samesite="lax", path="/")
        return response

    async def authorize(self, request):
        try:
            if request.method == "GET":
                self.rate_limit(request, "authorize")
                authorization = await run_in_threadpool(self.auth.authorization_request, query_parameters(request))
                nonce = await run_in_threadpool(self.auth.create_pending, authorization)
                return self.login_form(authorization, nonce)
            self.rate_limit(request, "login")
            origin = request.headers.get("origin")
            if origin is not None and origin != self.auth.base_url:
                raise AuthError("invalid_request", 403)
            data = await form_parameters(request)
            nonce = data.get("csrf_nonce", "")
            cookie = request.cookies.get(COOKIE, "")
            if not nonce or len(nonce) > 128 or not secrets.compare_digest(nonce.encode("utf-8"), cookie.encode("utf-8")):
                raise AuthError("invalid_request", 403)
            authorization = await run_in_threadpool(self.auth.pending_request, nonce)
            decision = data.get("decision")
            if decision not in ("allow", "deny"):
                raise AuthError("invalid_request")
            denied = decision == "deny"
            selected = frozenset(name for name in SCOPES if data.get("scope_" + name) == "yes")
            if not denied:
                valid = await run_in_threadpool(verify_password, data.get("password", ""), self.auth.password)
                requested = parse_scopes(authorization["scope"])
                if not valid or not selected & TOOL_SCOPES or not selected <= requested:
                    return self.login_form(authorization, nonce, error=True)
            authorization, code = await run_in_threadpool(self.auth.authorize, nonce, selected, denied)
            result = {"iss": self.auth.base_url}
            if authorization["state"]:
                result["state"] = authorization["state"]
            if denied:
                result["error"] = "access_denied"
            else:
                result["code"] = code
            response = RedirectResponse(authorization["redirect_uri"] + "?" + urlencode(result), status_code=303)
            response.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="lax")
            return response
        except AuthError as exc:
            return oauth_error(exc)

    async def token(self, request):
        try:
            self.rate_limit(request, "token")
            if request.headers.get("authorization"):
                raise AuthError("invalid_client", 401)
            data = await form_parameters(request)
            return JSONResponse(await run_in_threadpool(self.auth.exchange, data))
        except AuthError as exc:
            return oauth_error(exc)

    async def revoke(self, request):
        try:
            self.rate_limit(request, "token")
            if request.headers.get("authorization"):
                raise AuthError("invalid_client", 401)
            await run_in_threadpool(self.auth.revoke, await form_parameters(request))
            return Response(status_code=200)
        except AuthError as exc:
            return oauth_error(exc)

    async def mcp(self, request):
        if request.method != "POST":
            return Response(status_code=405, headers={"Allow": "POST"})
        version = request.headers.get("mcp-protocol-version")
        if version is not None and version not in VERSIONS:
            return rpc_error(None, -32600, "Unsupported protocol version", status=400)
        accept = request.headers.get("accept", "*/*")
        accepted = {part.split(";", 1)[0].strip().lower() for part in accept.split(",")}
        if not accepted & {"application/json", "*/*", "application/*"}:
            return Response(status_code=406)
        try:
            message = await json_body(request)
        except AuthError as exc:
            code = -32700 if exc.status == 400 else -32600
            return rpc_error(None, code, "Invalid JSON request", status=exc.status)
        if not isinstance(message, dict):
            return rpc_error(None, -32600, "Invalid request", status=400)
        identifier = message.get("id")
        if identifier is not None and (type(identifier) not in (str, int) or isinstance(identifier, str) and len(identifier) > 256):
            return rpc_error(None, -32600, "Invalid request", status=400)
        method = message.get("method")
        params = message.get("params", {})
        if message.get("jsonrpc") != "2.0" or not isinstance(method, str) or not isinstance(params, dict):
            return rpc_error(identifier, -32600, "Invalid request", status=400)
        if "id" not in message:
            return Response(status_code=202)
        if method == "initialize":
            proposed = params.get("protocolVersion")
            if (
                not isinstance(proposed, str)
                or not isinstance(params.get("capabilities"), dict)
                or not isinstance(params.get("clientInfo"), dict)
                or not isinstance(params["clientInfo"].get("name"), str)
                or not isinstance(params["clientInfo"].get("version"), str)
            ):
                return rpc_error(identifier, -32602, "Invalid initialize parameters")
            return rpc_result(identifier, {
                "protocolVersion": proposed if proposed in VERSIONS else VERSIONS[-1],
                "capabilities": {"tools": {"listChanged": False}, **({"events": {}} if self.events is not None and self.events.enabled else {})},
                "serverInfo": {"name": "hermes-dot-mcp", "version": "1.0.0"},
            })
        if method == "ping":
            return rpc_result(identifier, {})
        granted = request.scope["principal"]["scopes"]
        if method == "tools/list":
            if params.get("cursor") is not None:
                return rpc_error(identifier, -32602, "Invalid cursor")
            tools = [tool for tool in self.tools.values() if set(tool["_meta"]["requiredScopes"]) <= granted]
            return rpc_result(identifier, {"tools": tools})
        if method != "tools/call":
            if method.startswith("events/") and self.events is not None:
                if "hermes.read" not in granted:
                    return rpc_error(identifier, -32003, "Insufficient scope", status=403)
                try:
                    async with asyncio.timeout(self.timeout):
                        async with self.capacity:
                            await run_in_threadpool(self.auth.authenticate, request.headers["authorization"].split(" ", 1)[1])
                            result = await self.events.dispatch(method, params, request.scope["principal"])
                    return rpc_result(identifier, result)
                except EventsError as exc:
                    return rpc_error(identifier, exc.code, exc.message, data=exc.data)
                except AuthError:
                    return JSONResponse(
                        {"error": "invalid_token"}, status_code=401,
                        headers={"WWW-Authenticate": challenge(self.auth)},
                    )
                except Exception:
                    return rpc_error(identifier, -32603, "Event operation failed")
            return rpc_error(identifier, -32601, "Method not found")
        name = params.get("name")
        args = params.get("arguments", {})
        if not isinstance(name, str) or not isinstance(args, dict):
            return rpc_error(identifier, -32602, "Invalid tool parameters")
        tool = self.tools.get(name)
        if tool is None:
            return rpc_error(identifier, -32602, "Unknown tool")
        required = frozenset(tool["_meta"]["requiredScopes"])
        if not required <= granted:
            auth_header = challenge(self.auth, "insufficient_scope", required)
            return rpc_result(identifier, {
                "content": [{"type": "text", "text": "Additional owner consent is required for this tool."}],
                "isError": True,
                "_meta": {"mcp/www_authenticate": [auth_header]},
            }, status=403, headers={"WWW-Authenticate": auth_header})
        try:
            async with asyncio.timeout(self.timeout):
                async with self.capacity:
                    await run_in_threadpool(self.auth.authenticate, request.headers["authorization"].split(" ", 1)[1])
                    result = await self.backend.call(name, args)
            text = json.dumps(result, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
            text.encode("utf-8")
            response = {"content": [{"type": "text", "text": text}], "isError": isinstance(result, dict) and result.get("ok") is False}
            if isinstance(result, dict):
                response["structuredContent"] = result
            return rpc_result(identifier, response)
        except AuthError:
            return JSONResponse(
                {"error": "invalid_token"}, status_code=401,
                headers={"WWW-Authenticate": challenge(self.auth)},
            )
        except Exception:
            return rpc_result(identifier, {
                "content": [{"type": "text", "text": "Tool execution failed."}],
                "isError": True,
            })


def create_app(settings, backend=None, events=None):
    if not isinstance(settings, dict):
        raise ValueError("Configuration must be a JSON object")
    host = settings.get("host", "127.0.0.1")
    port = settings.get("port", 8765)
    if host != "127.0.0.1" or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Server must bind to 127.0.0.1 on a valid port")
    if backend is None:
        from backend import Backend
        backend_settings = settings.get("backend", {})
        if not isinstance(backend_settings, dict):
            raise ValueError("backend settings must be an object")
        backend = Backend(backend_settings)
    service = Service(settings, backend, events)
    @asynccontextmanager
    async def lifespan(app):
        if service.events is not None:
            await service.events.start()
        try:
            yield
        finally:
            if service.events is not None:
                await service.events.close()

    methods = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"]
    app = Starlette(routes=[
        Route("/healthz", service.health, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource", service.resource_metadata, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource/mcp", service.resource_metadata, methods=["GET"]),
        Route("/.well-known/oauth-authorization-server", service.authorization_metadata, methods=["GET"]),
        Route("/register", service.register, methods=["POST"]),
        Route("/authorize", service.authorize, methods=["GET", "POST"]),
        Route("/token", service.token, methods=["POST"]),
        Route("/revoke", service.revoke, methods=["POST"]),
        Route("/mcp", service.mcp, methods=methods),
    ], debug=False, lifespan=lifespan)
    app.router.redirect_slashes = False
    return SecurityBoundary(app, service.auth, port)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    try:
        path = Path(args.config).expanduser()
        with path.open("rb") as stream:
            raw = stream.read(BODY_LIMIT + 1)
        if len(raw) > BODY_LIMIT:
            raise ValueError("Configuration too large")
        settings = json_loads(raw)
        app = create_app(settings)
    except Exception:
        raise SystemExit("Unable to initialize server; check configuration and backend availability.") from None
    for name in ("httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.CRITICAL)
    uvicorn.run(
        app, host="127.0.0.1", port=settings.get("port", 8765),
        access_log=False, proxy_headers=False, forwarded_allow_ips="",
        server_header=False, log_level="warning", limit_concurrency=64,
        h11_max_incomplete_event_size=BODY_LIMIT, timeout_keep_alive=5,
    )


if __name__ == "__main__":
    main()
