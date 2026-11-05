import asyncio
import base64
import hashlib
import hmac
import inspect
import ipaddress
import json
import logging
import math
import os
import secrets
import socket
import sqlite3
import stat
import threading
import time
from collections.abc import Mapping
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from weakref import WeakValueDictionary


EVENT_NAME = "hermes.message.created"
MAX_TTL_MS = 86400000
MAX_BODY = 262144
MAX_RESPONSE = 65536
LOG = logging.getLogger(__name__)


class EventsError(Exception):
    def __init__(self, code, message, reason=None):
        self.code = code
        self.message = message
        self.data = {"reason": reason} if reason else None
        super().__init__(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def instant(value):
    if isinstance(value, bool):
        raise ValueError("Invalid event timestamp")
    if isinstance(value, (int, float)):
        if not math.isfinite(value):
            raise ValueError("Invalid event timestamp")
        if value > 100000000000:
            value /= 1000
        parsed = datetime.fromtimestamp(value, timezone.utc)
    elif isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("Event timestamp requires a timezone")
    else:
        raise ValueError("Missing event timestamp")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def public_address(value):
    address = ipaddress.ip_address(value)
    if not address.is_global or address.is_multicast or address.is_reserved:
        return False
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped or address.sixtofour or address.teredo:
            return False
        if address in ipaddress.ip_network("64:ff9b::/96") or address in ipaddress.ip_network("64:ff9b:1::/48"):
            return False
    return True


def callback_url(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 4096:
        raise EventsError(-32602, "Invalid callback URL")
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https" or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.port not in (None, 443) or parsed.query or parsed.fragment
            or "?" in value or "#" in value or "\\" in value
            or any(ord(character) <= 32 or ord(character) >= 127 for character in value)
            or "%" in parsed.netloc
        ):
            raise ValueError
        try:
            literal = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            literal = None
        if literal is not None and not public_address(str(literal)):
            raise ValueError
    except ValueError as exc:
        raise EventsError(-32602, "Invalid callback URL") from exc
    return value


def signing_key(value):
    if not isinstance(value, str) or not value.startswith("whsec_") or len(value) > 100:
        raise EventsError(-32602, "Invalid webhook signing secret")
    try:
        key = base64.b64decode(value[6:], validate=True)
    except (ValueError, TypeError) as exc:
        raise EventsError(-32602, "Invalid webhook signing secret") from exc
    if not 24 <= len(key) <= 64:
        raise EventsError(-32602, "Invalid webhook signing secret")
    return key


class PublicResolver:
    async def resolve(self, host, port=443, family=socket.AF_UNSPEC):
        if port != 443:
            raise OSError("Callback port is not permitted")
        records = await asyncio.get_running_loop().getaddrinfo(
            host, port, family=family, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP,
        )
        if not records or any(not public_address(record[4][0]) for record in records):
            raise OSError("Callback destination is not public")
        result = []
        seen = set()
        for address_family, _, protocol, _, address in records:
            identity = (address_family, address[0])
            if identity not in seen:
                seen.add(identity)
                result.append({
                    "hostname": host, "host": address[0], "port": port,
                    "family": address_family, "proto": protocol,
                    "flags": socket.AI_NUMERICHOST,
                })
        return result

    async def close(self):
        return None


class Events:
    def __init__(self, settings, backend, grant_active, read_events=None):
        self.settings = settings
        self.backend = backend
        self.grant_active = grant_active
        self.read_events = read_events or settings.get("events_read_events")
        self.adapter = settings.get("events_adapter")
        self.path = Path(settings.get("events_db_path", settings.get("db_path", "~/.hermes/hermes-dot-mcp/events/events.sqlite3"))).expanduser().absolute()
        auth_path = settings.get("auth_db_path")
        if auth_path is not None and self.path == Path(auth_path).expanduser().absolute():
            raise ValueError("Events require a separate private database")
        self.default_ttl = settings.get("events_default_ttl_ms", 3600000)
        if type(self.default_ttl) is not int or not 1000 <= self.default_ttl <= MAX_TTL_MS:
            raise ValueError("events_default_ttl_ms must be between 1000 and 86400000")
        self.summary_bytes = settings.get("events_summary_bytes", 16384)
        if type(self.summary_bytes) is not int or not 256 <= self.summary_bytes <= 65536:
            raise ValueError("events_summary_bytes must be between 256 and 65536")
        self._db_lock = threading.RLock()
        self._locks = WeakValueDictionary()
        self._verified = {}
        self._task = None
        self._http = None
        self._closing = False

    @property
    def enabled(self):
        return True

    async def start(self):
        if self._task is not None:
            return
        import aiohttp
        await asyncio.to_thread(self._initialize)
        self._closing = False
        connector = aiohttp.TCPConnector(
            resolver=PublicResolver(), use_dns_cache=False, force_close=True,
            limit=8, family=socket.AF_UNSPEC, ssl=True,
        )
        self._http = aiohttp.ClientSession(
            connector=connector, timeout=aiohttp.ClientTimeout(total=10),
            trust_env=False, auto_decompress=False, cookie_jar=aiohttp.DummyCookieJar(),
        )
        self._task = asyncio.create_task(self._run(), name="hermes-mcp-events")

    async def close(self):
        self._closing = True
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        if self._http is not None:
            await self._http.close()
            self._http = None
        self._verified.clear()

    def _initialize(self):
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.path.parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("Events database directory must be owned by this user and mode 0700")
        descriptor = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise ValueError("Events database must be a private regular file")
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
        with self._connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS subscriptions (
                    id TEXT PRIMARY KEY,
                    grant_id TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    principal TEXT NOT NULL,
                    arguments TEXT NOT NULL,
                    callback TEXT NOT NULL,
                    secret TEXT NOT NULL,
                    old_secret TEXT,
                    old_until REAL,
                    expires REAL NOT NULL,
                    created REAL NOT NULL,
                    scan_cursor INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS pending (
                    subscription_id TEXT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
                    event_id TEXT NOT NULL,
                    cursor INTEGER NOT NULL,
                    body BLOB NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt REAL,
                    PRIMARY KEY(subscription_id, event_id)
                );
                CREATE INDEX IF NOT EXISTS pending_due ON pending(next_attempt);
            """)

    @contextmanager
    def _connection(self):
        with self._db_lock:
            db = sqlite3.connect(str(self.path), timeout=5, isolation_level=None)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys = ON")
            db.execute("PRAGMA secure_delete = ON")
            db.execute("PRAGMA synchronous = FULL")
            try:
                db.execute("BEGIN IMMEDIATE")
                yield db
                db.commit()
            except BaseException:
                db.rollback()
                raise
            finally:
                db.close()

    async def _db(self, operation, *args):
        return await asyncio.to_thread(operation, *args)

    def _lock(self, identifier):
        lock = self._locks.get(identifier)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[identifier] = lock
        return lock

    async def _active(self, principal):
        if inspect.iscoroutinefunction(self.grant_active):
            result = await self.grant_active(principal)
        else:
            result = await asyncio.to_thread(self.grant_active, principal)
        if inspect.isawaitable(result):
            result = await result
        if isinstance(result, Mapping):
            scopes = result.get("scopes", ())
            if isinstance(scopes, str):
                scopes = scopes.split()
            return (
                result.get("grant_id") == principal["grant_id"]
                and result.get("client_id") == principal["client_id"]
                and "hermes.read" in scopes
                and not result.get("revoked", False)
                and isinstance(result.get("expires"), (int, float))
                and result["expires"] > time.time()
            )
        return result is True

    async def _principal(self, principal):
        if not isinstance(principal, Mapping):
            raise EventsError(-32001, "Authorization required")
        scopes = principal.get("scopes", ())
        if isinstance(scopes, str):
            scopes = scopes.split()
        if not isinstance(scopes, (list, tuple, set, frozenset)) or "hermes.read" not in scopes:
            raise EventsError(-32001, "hermes.read is required")
        result = {}
        for field in ("grant_id", "client_id"):
            value = principal.get(field)
            if not isinstance(value, str) or not 1 <= len(value) <= 512:
                raise EventsError(-32001, "Authorization required")
            result[field] = value
        result["scopes"] = sorted(scopes)
        for field in ("owner_id", "user_id", "subject", "sub"):
            if field in principal:
                if not isinstance(principal[field], str) or not 1 <= len(principal[field]) <= 512:
                    raise EventsError(-32001, "Invalid account identity")
                result[field] = principal[field]
        if not await self._active(result):
            raise EventsError(-32001, "Grant is expired, revoked, or lacks hermes.read")
        return result

    async def call(self, method, params, principal):
        if self._http is None or self._closing:
            raise EventsError(-32603, "Events are not running")
        principal = await self._principal(principal)
        if params is None:
            params = {}
        if not isinstance(params, dict):
            raise EventsError(-32602, "Expected object parameters")
        if method == "events/list":
            if set(params) - {"cursor"} or params.get("cursor") is not None:
                raise EventsError(-32602, "Unsupported event catalog cursor")
            return {"events": [self._definition()]}
        if method not in ("events/subscribe", "events/unsubscribe"):
            raise EventsError(-32601, "Method not found")
        allowed = {"name", "arguments", "delivery"}
        if method == "events/subscribe":
            allowed |= {"cursor", "ttlMs"}
        if set(params) - allowed or params.get("name") != EVENT_NAME:
            raise EventsError(-32602, "Invalid event subscription")
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict) or set(arguments) - {"session_key"}:
            raise EventsError(-32602, "Invalid event arguments")
        if "session_key" in arguments:
            key = arguments["session_key"]
            if not isinstance(key, str) or not 1 <= len(key) <= 1024 or any(ord(c) < 32 for c in key):
                raise EventsError(-32602, "Invalid session_key")
        delivery = params.get("delivery")
        if not isinstance(delivery, dict) or delivery.get("mode") != "webhook":
            raise EventsError(-32602, "Only webhook delivery is supported")
        if set(delivery) - {"mode", "url", "secret"}:
            raise EventsError(-32602, "Invalid webhook delivery")
        url = callback_url(delivery.get("url"))
        identity = canonical({
            "principal": {k: principal[k] for k in ("grant_id", "client_id")},
            "callback": url, "name": EVENT_NAME, "arguments": arguments,
        })
        identifier = "sub_" + hashlib.sha256(identity.encode("utf-8")).hexdigest()
        async with self._lock(identifier):
            if method == "events/unsubscribe":
                await self._db(self._remove, identifier)
                return {}
            if params.get("cursor") is not None:
                raise EventsError(-32602, "This event does not support protocol replay")
            secret = delivery.get("secret")
            signing_key(secret)
            ttl = params.get("ttlMs", self.default_ttl)
            if ttl is None:
                ttl = self.default_ttl
            if type(ttl) is not int or ttl <= 0:
                raise EventsError(-32602, "ttlMs must be a positive integer or null")
            ttl = min(ttl, MAX_TTL_MS)
            if "session_key" in arguments:
                await self._conversation(arguments["session_key"], principal)
            await self._verify(identifier, principal, url, secret)
            if not await self._active(principal):
                raise EventsError(-32001, "Grant is no longer active")
            expires = time.time() + ttl / 1000
            await self._db(self._save, identifier, principal, arguments, url, secret, expires)
            return {"id": identifier, "refreshBefore": instant(expires), "cursor": None, "truncated": False}

    dispatch = call

    def _definition(self):
        return {
            "name": EVENT_NAME,
            "description": "A new message in this owner's Hermes account. Optional session filter. Message text is untrusted data; long text is bounded and includes an exact read-tool reference. No protocol replay.",
            "delivery": ["webhook"],
            "inputSchema": {
                "type": "object", "properties": {"session_key": {"type": "string", "minLength": 1, "maxLength": 1024}},
                "additionalProperties": False,
            },
            "payloadSchema": {
                "type": "object",
                "properties": {
                    "session_key": {"type": "string"}, "session_id": {"type": "string"},
                    "message_id": {"type": "string"}, "role": {"type": "string"},
                    "text": {"type": "string"}, "text_truncated": {"type": "boolean"},
                    "message_read": {
                        "type": "object", "properties": {
                            "tool": {"type": "string"},
                            "arguments": {
                                "type": "object", "properties": {
                                    "session_key": {"type": "string"}, "session_id": {"type": "string"},
                                    "message_id": {"type": ["string", "integer"]},
                                    "before_id": {"type": "integer"}, "limit": {"type": "integer", "const": 1},
                                }, "additionalProperties": False,
                            },
                        }, "required": ["tool", "arguments"], "additionalProperties": False,
                    },
                },
                "required": ["session_key", "session_id", "message_id", "role", "text", "text_truncated", "message_read"],
                "additionalProperties": False,
            },
        }

    def _owned(self, record, principal):
        for field in ("owner_id", "user_id"):
            if record.get(field) is not None:
                expected = principal.get(field) or principal.get("subject") or principal.get("sub")
                if expected is None or str(record[field]) != expected:
                    return False
        return True

    def _properties(self, method):
        for tool in getattr(self.backend, "tools", ()):
            if tool.get("name") == method:
                return tool.get("inputSchema", {}).get("properties", {})
        return None

    async def _conversation(self, session_key, principal, session_id=None):
        properties = self._properties("conversation_get")
        if properties is None or "session_key" in properties:
            arguments = {"session_key": session_key} if session_key is not None else {"session_id": session_id}
        else:
            if session_id is None:
                cursor = None
                for _ in range(100):
                    arguments = {"limit": 100}
                    if cursor is not None:
                        arguments["cursor"] = cursor
                    page = await self.backend.call("topics_list", arguments)
                    if not isinstance(page, Mapping) or not isinstance(page.get("topics"), list):
                        raise EventsError(-32001, "Conversation is unavailable")
                    for topic in page["topics"]:
                        if isinstance(topic, Mapping) and topic.get("session_key") == session_key and self._owned(topic, principal):
                            session_id = topic.get("session_id", topic.get("id"))
                            break
                    if session_id is not None or not page.get("has_more"):
                        break
                    next_cursor = page.get("next_cursor")
                    if not isinstance(next_cursor, str) or next_cursor == cursor:
                        raise EventsError(-32001, "Conversation is unavailable")
                    cursor = next_cursor
            if not isinstance(session_id, str) or not session_id:
                raise EventsError(-32001, "Conversation is unavailable")
            arguments = {"session_id": session_id}
        result = await self.backend.call("conversation_get", arguments)
        if not isinstance(result, Mapping) or result.get("error") or result.get("isError") or result.get("ok") is False:
            raise EventsError(-32001, "Conversation is unavailable")
        conversation = result.get("conversation", result.get("session", result))
        if not isinstance(conversation, Mapping) or not conversation or not self._owned(conversation, principal):
            raise EventsError(-32001, "Conversation is unavailable")
        returned_key = conversation.get("session_key", conversation.get("key"))
        if not isinstance(returned_key, str) or not returned_key or (session_key is not None and returned_key != session_key):
            raise EventsError(-32001, "Conversation is unavailable")
        return conversation

    def _save(self, identifier, principal, arguments, url, secret, expires):
        now = time.time()
        with self._connection() as db:
            existing = db.execute("SELECT * FROM subscriptions WHERE id = ?", (identifier,)).fetchone()
            if existing is not None and existing["expires"] <= now:
                db.execute("DELETE FROM subscriptions WHERE id = ?", (identifier,))
                existing = None
            if existing is None:
                if db.execute("SELECT count(*) FROM subscriptions").fetchone()[0] >= 100:
                    raise EventsError(-32000, "Subscription limit reached")
                db.execute(
                    "INSERT INTO subscriptions (id, grant_id, client_id, principal, arguments, callback, secret, expires, created) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (identifier, principal["grant_id"], principal["client_id"], canonical(principal), canonical(arguments), url, secret, expires, now),
                )
            else:
                old_secret, old_until = existing["old_secret"], existing["old_until"]
                if existing["secret"] != secret:
                    old_secret, old_until = existing["secret"], now + 300
                if old_until is not None and old_until <= now:
                    old_secret, old_until = None, None
                db.execute(
                    "UPDATE subscriptions SET principal = ?, secret = ?, old_secret = ?, old_until = ?, expires = ? WHERE id = ?",
                    (canonical(principal), secret, old_secret, old_until, expires, identifier),
                )

    def _remove(self, identifier):
        with self._connection() as db:
            db.execute("DELETE FROM subscriptions WHERE id = ?", (identifier,))

    def _subscription(self, identifier):
        with self._connection() as db:
            row = db.execute("SELECT * FROM subscriptions WHERE id = ?", (identifier,)).fetchone()
            return dict(row) if row is not None else None

    def _subscriptions(self):
        with self._connection() as db:
            now = time.time()
            db.execute("DELETE FROM subscriptions WHERE expires <= ?", (now,))
            db.execute("UPDATE subscriptions SET old_secret = NULL, old_until = NULL WHERE old_until <= ?", (now,))
            return [dict(row) for row in db.execute("SELECT * FROM subscriptions ORDER BY id")]

    async def _verify(self, identifier, principal, url, secret):
        now = time.monotonic()
        self._verified = {key: expiry for key, expiry in self._verified.items() if expiry > now}
        cache_key = hashlib.sha256(canonical([principal["grant_id"], principal["client_id"], url, secret]).encode("utf-8")).hexdigest()
        if self._verified.get(cache_key, 0) > now:
            return
        challenge = secrets.token_urlsafe(32)
        body = canonical({"type": "verification", "challenge": challenge}).encode("utf-8")
        try:
            status, response = await self._post(
                url, identifier, "msg_verification_" + secrets.token_urlsafe(24), body, [secret],
            )
            answer = json.loads(response) if 200 <= status < 300 else None
            echoed = answer.get("challenge") if isinstance(answer, dict) else None
            if not isinstance(echoed, str) or not hmac.compare_digest(echoed.encode("utf-8"), challenge.encode("utf-8")):
                raise EventsError(-32015, "CallbackEndpointError", "challenge_failed")
        except EventsError:
            raise
        except (asyncio.TimeoutError, TimeoutError) as exc:
            raise EventsError(-32015, "CallbackEndpointError", "timeout") from exc
        except Exception as exc:
            raise EventsError(-32015, "CallbackEndpointError", "connection_failed") from exc
        if len(self._verified) >= 1000:
            self._verified.clear()
        self._verified[cache_key] = time.monotonic() + 60

    async def _post(self, url, identifier, event_id, body, keys):
        callback_url(url)
        if len(body) > MAX_BODY:
            raise ValueError("Event body exceeds limit")
        stamp = str(int(time.time()))
        signed = event_id.encode("ascii") + b"." + stamp.encode("ascii") + b"." + body
        signatures = ["v1," + base64.b64encode(hmac.new(signing_key(key), signed, hashlib.sha256).digest()).decode("ascii") for key in keys]
        headers = {
            "Content-Type": "application/json", "webhook-id": event_id,
            "webhook-timestamp": stamp, "webhook-signature": " ".join(signatures),
            "X-MCP-Subscription-Id": identifier, "Accept-Encoding": "identity",
        }
        async with asyncio.timeout(10):
            async with self._http.post(url, data=body, headers=headers, allow_redirects=False, proxy=None) as response:
                if response.status in (410, 413):
                    return response.status, b""
                chunks = []
                size = 0
                async for chunk in response.content.iter_chunked(8192):
                    size += len(chunk)
                    if size > MAX_RESPONSE:
                        raise EventsError(-32015, "CallbackEndpointError", "response_too_large")
                    chunks.append(chunk)
                return response.status, b"".join(chunks)

    async def _read(self, cursor, principal):
        if self.read_events is None:
            properties = self._properties("events_poll")
            field = "cursor" if properties is not None and "cursor" in properties and "after_cursor" not in properties else "after_cursor"
            result = await self.backend.call("events_poll", {field: cursor, "limit": 100})
        else:
            result = self.read_events(cursor, 100)
            if inspect.isawaitable(result):
                result = await result
        if self.adapter is not None:
            result = self.adapter(result)
            if inspect.isawaitable(result):
                result = await result
        scan_cursor = None
        if isinstance(result, Mapping):
            if result.get("error") or result.get("isError"):
                raise ValueError("Backend event poll failed")
            if result.get("has_more") is False:
                scan_cursor = result.get("cursor", result.get("next_cursor"))
            for field in ("events", "items", "rows"):
                if field in result:
                    result = result[field]
                    break
        if not isinstance(result, list) or len(result) > 100:
            raise ValueError("events_poll must return at most 100 event records")
        events = []
        conversations = {}
        for row in result:
            if isinstance(row, Mapping) and not row.get("session_key") and row.get("session_id") is not None:
                session_id = str(row["session_id"])
                if session_id not in conversations:
                    conversations[session_id] = await self._conversation(None, principal, session_id)
                row = {**row, "session_key": conversations[session_id]["session_key"]}
            events.append(self._event(row))
        previous = cursor
        for event in events:
            if event["cursor"] <= previous:
                raise ValueError("Event cursors must be strictly increasing")
            previous = event["cursor"]
        if scan_cursor is not None:
            if type(scan_cursor) is not int or not previous <= scan_cursor <= 9223372036854775807:
                raise ValueError("Invalid backend scan cursor")
            if scan_cursor > previous:
                events.append({"cursor": scan_cursor, "ignored": True})
        return events

    def _event(self, row):
        if not isinstance(row, Mapping):
            raise ValueError("Invalid backend event")
        event = dict(row)
        cursor = event.get("cursor", event.get("event_cursor", event.get("sequence", event.get("seq", event.get("id")))))
        if type(cursor) is not int or not 0 < cursor <= 9223372036854775807:
            raise ValueError("Missing integer event cursor")
        event["cursor"] = cursor
        kind = event.get("name", event.get("event_type", event.get("type")))
        if kind is not None and kind not in (EVENT_NAME, "message.created", "message_created"):
            return {"cursor": cursor, "ignored": True}
        data = event.get("data", event.get("payload"))
        if isinstance(data, Mapping):
            event = {**event, **data, "cursor": cursor}
        metadata = event.get("metadata", {})
        if not isinstance(metadata, Mapping):
            metadata = {}
        origins = [event.get("origin"), event.get("source"), metadata.get("origin"), metadata.get("source"), metadata.get("client")]
        if event.get("from_dot") is True or metadata.get("from_dot") is True or any(
            isinstance(origin, str) and origin.lower() in {"dot", "dots", "chatgpt-dot", "hermes-dot-mcp"}
            for origin in origins
        ):
            return {"cursor": cursor, "ignored": True}
        for target, aliases in {
            "session_key": ("session_key",), "session_id": ("session_id",),
            "message_id": ("message_id", "id"), "role": ("role",), "text": ("text", "content"),
            "timestamp": ("timestamp", "created_at", "created"),
        }.items():
            for field in aliases:
                if event.get(field) is not None:
                    event[target] = event[field]
                    break
            else:
                raise ValueError("Missing backend event field: " + target)
        for field in ("session_key", "session_id", "message_id", "role"):
            value = event[field]
            if field in ("session_id", "message_id") and type(value) is int:
                value = str(value)
            if not isinstance(value, str) or not 1 <= len(value) <= 1024:
                raise ValueError("Invalid backend event identity")
            value.encode("utf-8")
            event[field] = value
        if not isinstance(event["text"], str):
            raise ValueError("Backend event text must be a string")
        event["timestamp"] = instant(event["timestamp"])
        return event

    def _stage(self, subscription, events):
        with self._connection() as db:
            row = db.execute("SELECT * FROM subscriptions WHERE id = ?", (subscription["id"],)).fetchone()
            if row is None or row["expires"] <= time.time() or row["scan_cursor"] != subscription["scan_cursor"] or row["created"] != subscription["created"]:
                return
            arguments, principal = json.loads(row["arguments"]), json.loads(row["principal"])
            for event in events:
                if event.get("ignored") or not self._owned(event, principal):
                    continue
                if arguments.get("session_key") is not None and arguments["session_key"] != event["session_key"]:
                    continue
                occurred = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")).timestamp()
                if occurred < int(row["created"]):
                    continue
                raw_text = event["text"].encode("utf-8")
                text = raw_text[:self.summary_bytes].decode("utf-8", errors="ignore")
                data = {field: event[field] for field in ("session_key", "session_id", "message_id", "role")}
                data.update({
                    "text": text, "text_truncated": text != event["text"],
                    "message_read": self._reference(event),
                })
                identity = canonical([EVENT_NAME, event["cursor"], event["session_key"], event["session_id"], event["message_id"]])
                event_id = "evt_" + hashlib.sha256(identity.encode("utf-8")).hexdigest()
                body = canonical({"eventId": event_id, "name": EVENT_NAME, "timestamp": event["timestamp"], "data": data, "cursor": None}).encode("utf-8")
                while len(body) > MAX_BODY and data["text"]:
                    data["text"] = data["text"][:len(data["text"]) // 2]
                    data["text_truncated"] = True
                    body = canonical({"eventId": event_id, "name": EVENT_NAME, "timestamp": event["timestamp"], "data": data, "cursor": None}).encode("utf-8")
                if len(body) > MAX_BODY:
                    raise ValueError("Event exceeds maximum payload size")
                db.execute(
                    "INSERT OR IGNORE INTO pending (subscription_id, event_id, cursor, body, next_attempt) VALUES (?, ?, ?, ?, ?)",
                    (row["id"], event_id, event["cursor"], body, time.time()),
                )
            if events:
                db.execute("UPDATE subscriptions SET scan_cursor = ? WHERE id = ?", (events[-1]["cursor"], row["id"]))

    def _reference(self, event):
        properties = self._properties("message_read")
        if properties is not None or not hasattr(self.backend, "tools"):
            arguments = {"session_id": event["session_id"]} if properties is not None and "session_id" in properties else {"session_key": event["session_key"]}
            message_id = event["message_id"]
            if properties is not None and properties.get("message_id", {}).get("type") == "integer":
                message_id = int(message_id)
            arguments["message_id"] = message_id
            return {"tool": "message_read", "arguments": arguments}
        if self._properties("messages_read") is not None:
            message_id = int(event["message_id"])
            if not 1 <= message_id <= 9223372036854775807:
                raise ValueError("Invalid backend message ID")
            arguments = {"session_id": event["session_id"], "limit": 1}
            if message_id < 9223372036854775807:
                arguments["before_id"] = message_id + 1
            return {"tool": "messages_read", "arguments": arguments}
        raise ValueError("A message_read or messages_read tool is required")

    def _pending_count(self, identifier):
        with self._connection() as db:
            return db.execute("SELECT count(*) FROM pending WHERE subscription_id = ?", (identifier,)).fetchone()[0]

    def _due(self, identifier):
        with self._connection() as db:
            return [dict(row) for row in db.execute(
                "SELECT * FROM pending WHERE subscription_id = ? AND next_attempt <= ? ORDER BY cursor LIMIT 10",
                (identifier, time.time()),
            )]

    def _ack(self, identifier, event_id):
        with self._connection() as db:
            db.execute("DELETE FROM pending WHERE subscription_id = ? AND event_id = ?", (identifier, event_id))

    def _retry(self, identifier, event_id):
        with self._connection() as db:
            row = db.execute("SELECT attempts FROM pending WHERE subscription_id = ? AND event_id = ?", (identifier, event_id)).fetchone()
            if row is None:
                return
            attempts = row["attempts"]
            next_attempt = None if attempts >= 8 else time.time() + min(300, 2 ** attempts) + secrets.randbelow(1000) / 1000
            db.execute(
                "UPDATE pending SET next_attempt = ? WHERE subscription_id = ? AND event_id = ?", (next_attempt, identifier, event_id),
            )

    def _attempt(self, identifier, event_id):
        with self._connection() as db:
            row = db.execute("SELECT attempts FROM pending WHERE subscription_id = ? AND event_id = ?", (identifier, event_id)).fetchone()
            if row is None or row["attempts"] >= 8:
                return False
            attempts = row["attempts"] + 1
            next_attempt = None if attempts >= 8 else time.time() + min(300, 2 ** attempts)
            db.execute(
                "UPDATE pending SET attempts = ?, next_attempt = ? WHERE subscription_id = ? AND event_id = ?",
                (attempts, next_attempt, identifier, event_id),
            )
            return True

    async def _deliver(self, identifier, item):
        async with self._lock(identifier):
            subscription = await self._db(self._subscription, identifier)
            if subscription is None:
                return
            principal = json.loads(subscription["principal"])
            if subscription["expires"] <= time.time() or not await self._active(principal):
                await self._db(self._remove, identifier)
                return
            body = bytes(item["body"])
            payload = json.loads(body)
            await self._conversation(payload["data"]["session_key"], principal, payload["data"]["session_id"])
            if subscription["expires"] <= time.time() or not await self._active(principal):
                await self._db(self._remove, identifier)
                return
            if not await self._db(self._attempt, identifier, item["event_id"]):
                return
            keys = [subscription["secret"]]
            if subscription["old_secret"] and subscription["old_until"] > time.time():
                keys.append(subscription["old_secret"])
            try:
                status, _ = await self._post(subscription["callback"], identifier, item["event_id"], body, keys)
            except asyncio.CancelledError:
                raise
            except Exception:
                await self._db(self._retry, identifier, item["event_id"])
                return
            if 200 <= status < 300:
                await self._db(self._ack, identifier, item["event_id"])
            elif status in (410, 413):
                await self._db(self._remove, identifier)
            elif status in (408, 425, 429) or status >= 500:
                await self._db(self._retry, identifier, item["event_id"])
            else:
                await self._db(self._remove, identifier)

    async def _tick(self, subscription):
        identifier = subscription["id"]
        principal = json.loads(subscription["principal"])
        if not await self._active(principal):
            async with self._lock(identifier):
                await self._db(self._remove, identifier)
            return
        if await self._db(self._pending_count, identifier) <= 900:
            events = await self._read(subscription["scan_cursor"], principal)
            await self._db(self._stage, subscription, events)

    async def _send_due(self, subscription):
        identifier = subscription["id"]
        for item in await self._db(self._due, identifier):
            try:
                await self._deliver(identifier, item)
            except EventsError as exc:
                if exc.code == -32001:
                    async with self._lock(identifier):
                        await self._db(self._remove, identifier)
                    return
                raise

    async def _run(self):
        poll_slots, send_slots = asyncio.Semaphore(4), asyncio.Semaphore(4)
        running = {}

        async def process(subscription, operation, slots):
            async with slots:
                try:
                    await operation(subscription)
                except asyncio.CancelledError:
                    raise
                except EventsError as exc:
                    if exc.code == -32001:
                        async with self._lock(subscription["id"]):
                            await self._db(self._remove, subscription["id"])
                    else:
                        LOG.warning("MCP events subscription paused: %s", type(exc).__name__)
                except Exception as exc:
                    LOG.warning("MCP events subscription paused: %s", type(exc).__name__)

        try:
            while not self._closing:
                started = time.monotonic()
                try:
                    subscriptions = await self._db(self._subscriptions)
                    running = {key: task for key, task in running.items() if not task.done()}
                    for subscription in subscriptions:
                        for kind, operation, slots in (("poll", self._tick, poll_slots), ("send", self._send_due, send_slots)):
                            key = (subscription["id"], kind)
                            if key not in running:
                                running[key] = asyncio.create_task(process(subscription, operation, slots))
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    LOG.warning("MCP events poll paused: %s", type(exc).__name__)
                await asyncio.sleep(max(0.05, 2 - (time.monotonic() - started)))
        finally:
            for task in running.values():
                task.cancel()
            await asyncio.gather(*running.values(), return_exceptions=True)
