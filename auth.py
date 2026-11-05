import base64
import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import time
from collections import defaultdict, deque
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit


SCOPES = frozenset({"hermes.read", "hermes.write", "hermes.control", "offline_access"})
TOOL_SCOPES = SCOPES - {"offline_access"}
CALLBACK = "https://chatgpt.com/connector_platform_oauth_redirect"
CALLBACK_PATTERN = re.compile(r"https://chatgpt\.com/connector/oauth/[A-Za-z0-9_-]{1,256}\Z")
PKCE_VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}\Z")
PKCE_CHALLENGE = re.compile(r"[A-Za-z0-9_-]{43}\Z")


class AuthError(Exception):
    def __init__(self, error, status=400):
        self.error = error
        self.status = status
        super().__init__(error)


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def encoded(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def parse_scopes(value, default=None):
    if value is None:
        if default is None:
            raise AuthError("invalid_scope")
        return frozenset(default)
    if not isinstance(value, str) or len(value) > 256:
        raise AuthError("invalid_scope")
    parts = value.split(" ")
    if not parts or any(not part or part not in SCOPES for part in parts):
        raise AuthError("invalid_scope")
    return frozenset(parts)


def scope_text(scopes):
    return " ".join(sorted(scopes))


def valid_callback(value):
    return isinstance(value, str) and (value == CALLBACK or CALLBACK_PATTERN.fullmatch(value) is not None)


def validate_base_url(value):
    if not isinstance(value, str):
        raise ValueError("base_url must be an HTTPS origin")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or any(character.isspace() for character in value)
    ):
        raise ValueError("base_url must be an HTTPS origin")
    parsed.port
    return value.rstrip("/")


def decode_hash_part(value):
    if re.fullmatch(r"[0-9a-fA-F]+", value) and len(value) % 2 == 0:
        return bytes.fromhex(value)
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


def password_parameters(value):
    if not isinstance(value, str):
        raise ValueError("login_password_hash must use scrypt$N$r$p$salt$hash")
    parts = value.split("$")
    if parts and parts[0] == "":
        parts = parts[1:]
    if len(parts) != 6 or parts[0] != "scrypt":
        raise ValueError("login_password_hash must use scrypt$N$r$p$salt$hash")
    try:
        n, r, p = map(int, parts[1:4])
        salt, expected = map(decode_hash_part, parts[4:])
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid scrypt password hash") from exc
    if (
        n < 16384 or n > 1048576 or n & (n - 1)
        or not 1 <= r <= 32 or not 1 <= p <= 16
        or 128 * n * r > 268435456
        or not 16 <= len(salt) <= 64
        or not 32 <= len(expected) <= 64
    ):
        raise ValueError("Invalid scrypt password parameters")
    return n, r, p, salt, expected


def verify_password(password, parameters):
    if not isinstance(password, str) or not 1 <= len(password) <= 1024:
        return False
    n, r, p, salt, expected = parameters
    try:
        candidate = hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
            dklen=len(expected), maxmem=536870912,
        )
    except (ValueError, UnicodeError):
        return False
    return secrets.compare_digest(candidate, expected)


class RateLimiter:
    def __init__(self):
        self.buckets = defaultdict(deque)

    def allow(self, category, address, per_address, total, window):
        now = time.monotonic()
        for key in list(self.buckets):
            bucket = self.buckets[key]
            while bucket and bucket[0] <= now - key[2]:
                bucket.popleft()
            if not bucket:
                del self.buckets[key]
        keys = ((category, address, window), (category, "*", window))
        if len(self.buckets[keys[0]]) >= per_address or len(self.buckets[keys[1]]) >= total:
            return False
        if len(self.buckets) > 4096:
            return False
        for key in keys:
            self.buckets[key].append(now)
        return True


class AuthStore:
    def __init__(self, settings):
        self.base_url = validate_base_url(settings["base_url"])
        self.resource = self.base_url + "/mcp"
        callbacks = settings.get("allowed_redirect_uris", [CALLBACK])
        if (
            not isinstance(callbacks, list) or not 1 <= len(callbacks) <= 32
            or not all(valid_callback(uri) for uri in callbacks)
        ):
            raise ValueError("allowed_redirect_uris must list exact documented ChatGPT HTTPS callbacks")
        self.callbacks = frozenset(callbacks)
        self.password = password_parameters(settings["login_password_hash"])
        self.path = Path(settings["db_path"]).expanduser().absolute()
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
        descriptor = os.open(self.path, flags, 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise ValueError("Auth database must be a private regular file owned by this user")
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
        self.limiter = RateLimiter()
        with self.connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS clients (
                    client_id TEXT PRIMARY KEY,
                    redirects TEXT NOT NULL,
                    scopes TEXT NOT NULL,
                    created INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS pending (
                    nonce_hash TEXT PRIMARY KEY,
                    request TEXT NOT NULL,
                    expires INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS grants (
                    grant_id TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL REFERENCES clients(client_id),
                    redirect_uri TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    scopes TEXT NOT NULL,
                    expires INTEGER NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS codes (
                    code_hash TEXT PRIMARY KEY,
                    grant_id TEXT NOT NULL REFERENCES grants(grant_id),
                    challenge TEXT NOT NULL,
                    expires INTEGER NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS tokens (
                    token_hash TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    grant_id TEXT NOT NULL REFERENCES grants(grant_id),
                    expires INTEGER NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS token_grants ON tokens(grant_id);
            """)

    @contextmanager
    def connection(self):
        db = sqlite3.connect(str(self.path), timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("PRAGMA secure_delete = ON")
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def cleanup(self, db, now):
        db.execute("DELETE FROM pending WHERE expires <= ?", (now,))
        db.execute("DELETE FROM codes WHERE expires <= ?", (now,))
        db.execute("DELETE FROM tokens WHERE expires <= ?", (now,))
        db.execute(
            "DELETE FROM grants WHERE expires <= ? AND grant_id NOT IN (SELECT grant_id FROM tokens) "
            "AND grant_id NOT IN (SELECT grant_id FROM codes)", (now,),
        )
        db.execute(
            "DELETE FROM clients WHERE created <= ? "
            "AND NOT EXISTS (SELECT 1 FROM grants g WHERE g.client_id = clients.client_id) "
            "AND NOT EXISTS (SELECT 1 FROM pending p WHERE json_extract(p.request, '$.client_id') = clients.client_id)",
            (now - 3600,),
        )

    def register(self, data):
        if not isinstance(data, dict):
            raise AuthError("invalid_client_metadata")
        redirects = data.get("redirect_uris")
        if (
            not isinstance(redirects, list) or not 1 <= len(redirects) <= 8
            or not all(valid_callback(uri) and uri in self.callbacks for uri in redirects)
            or len(set(redirects)) != len(redirects)
        ):
            raise AuthError("invalid_redirect_uri")
        if data.get("token_endpoint_auth_method", "none") != "none":
            raise AuthError("invalid_client_metadata")
        grants = data.get("grant_types", ["authorization_code", "refresh_token"])
        responses = data.get("response_types", ["code"])
        if (
            not isinstance(grants, list) or "authorization_code" not in grants
            or any(item not in ("authorization_code", "refresh_token") for item in grants)
            or responses != ["code"]
            or data.get("application_type", "web") != "web"
        ):
            raise AuthError("invalid_client_metadata")
        scopes = parse_scopes(data.get("scope"), SCOPES)
        if "refresh_token" not in grants:
            scopes = scopes - {"offline_access"}
        now = int(time.time())
        client_id = secrets.token_urlsafe(32)
        with self.connection() as db:
            self.cleanup(db, now)
            if db.execute("SELECT count(*) FROM clients").fetchone()[0] >= 1000:
                raise AuthError("temporarily_unavailable", 503)
            db.execute(
                "INSERT INTO clients VALUES (?, ?, ?, ?)",
                (client_id, json.dumps(redirects), scope_text(scopes), now),
            )
        return {
            "client_id": client_id,
            "client_id_issued_at": now,
            "redirect_uris": redirects,
            "token_endpoint_auth_method": "none",
            "grant_types": list(dict.fromkeys(grants)),
            "response_types": ["code"],
            "scope": scope_text(scopes),
        }

    def authorization_request(self, data):
        client_id = data.get("client_id")
        redirect = data.get("redirect_uri")
        if not isinstance(client_id, str) or not valid_callback(redirect) or redirect not in self.callbacks:
            raise AuthError("invalid_request")
        with self.connection() as db:
            client = db.execute("SELECT * FROM clients WHERE client_id = ?", (client_id,)).fetchone()
        if client is None or redirect not in json.loads(client["redirects"]):
            raise AuthError("invalid_request")
        if data.get("response_type") != "code":
            raise AuthError("unsupported_response_type")
        if data.get("resource") != self.resource:
            raise AuthError("invalid_target")
        scopes = parse_scopes(data.get("scope"), {"hermes.read"})
        if not scopes <= parse_scopes(client["scopes"]):
            raise AuthError("invalid_scope")
        if not scopes & TOOL_SCOPES:
            raise AuthError("invalid_scope")
        challenge = data.get("code_challenge", "")
        if data.get("code_challenge_method") != "S256" or not PKCE_CHALLENGE.fullmatch(challenge):
            raise AuthError("invalid_request")
        state = data.get("state", "")
        if not isinstance(state, str) or len(state) > 2048:
            raise AuthError("invalid_request")
        return {
            "client_id": client_id, "redirect_uri": redirect,
            "resource": self.resource, "scope": scope_text(scopes),
            "challenge": challenge, "state": state,
        }

    def create_pending(self, authorization):
        nonce = secrets.token_urlsafe(32)
        now = int(time.time())
        with self.connection() as db:
            self.cleanup(db, now)
            if db.execute("SELECT count(*) FROM pending").fetchone()[0] >= 1000:
                raise AuthError("temporarily_unavailable", 503)
            db.execute("INSERT INTO pending VALUES (?, ?, ?)", (digest(nonce), json.dumps(authorization), now + 600))
        return nonce

    def pending_request(self, nonce):
        if not isinstance(nonce, str) or not 32 <= len(nonce) <= 128:
            raise AuthError("invalid_request")
        with self.connection() as db:
            row = db.execute(
                "SELECT request FROM pending WHERE nonce_hash = ? AND expires > ?",
                (digest(nonce), int(time.time())),
            ).fetchone()
        if row is None:
            raise AuthError("invalid_request")
        return json.loads(row["request"])

    def authorize(self, nonce, selected, denied=False):
        now = int(time.time())
        with self.connection() as db:
            row = db.execute("SELECT * FROM pending WHERE nonce_hash = ?", (digest(nonce),)).fetchone()
            if row is None or row["expires"] <= now:
                raise AuthError("invalid_request")
            authorization = json.loads(row["request"])
            requested = parse_scopes(authorization["scope"])
            if not selected <= requested or (not denied and not selected & TOOL_SCOPES):
                raise AuthError("invalid_scope")
            db.execute("DELETE FROM pending WHERE nonce_hash = ?", (digest(nonce),))
            if denied:
                return authorization, None
            grant_id = secrets.token_urlsafe(32)
            code = secrets.token_urlsafe(32)
            db.execute(
                "INSERT INTO grants VALUES (?, ?, ?, ?, ?, ?, 0)",
                (grant_id, authorization["client_id"], authorization["redirect_uri"],
                 self.resource, scope_text(selected), now + 300),
            )
            db.execute("INSERT INTO codes VALUES (?, ?, ?, ?, 0)", (digest(code), grant_id, authorization["challenge"], now + 300))
            return authorization, code

    def issue_tokens(self, db, grant, now, initial=False):
        offline = "offline_access" in parse_scopes(grant["scopes"])
        grant_expires = grant["expires"]
        if initial:
            grant_expires = now + (2592000 if offline else 3600)
            db.execute("UPDATE grants SET expires = ? WHERE grant_id = ?", (grant_expires, grant["grant_id"]))
        access = secrets.token_urlsafe(48)
        expires = min(now + 3600, grant_expires)
        db.execute("INSERT INTO tokens VALUES (?, 'access', ?, ?, 0)", (digest(access), grant["grant_id"], expires))
        result = {
            "access_token": access, "token_type": "Bearer", "expires_in": expires - now,
            "scope": grant["scopes"], "resource": grant["resource"],
        }
        if offline:
            refresh = secrets.token_urlsafe(48)
            db.execute(
                "INSERT INTO tokens VALUES (?, 'refresh', ?, ?, 0)",
                (digest(refresh), grant["grant_id"], grant_expires),
            )
            result["refresh_token"] = refresh
        return result

    def exchange(self, data):
        client_id = data.get("client_id")
        if not isinstance(client_id, str) or not client_id or len(client_id) > 128:
            raise AuthError("invalid_client", 401)
        if data.get("client_secret") is not None or data.get("client_assertion") is not None:
            raise AuthError("invalid_client", 401)
        if data.get("resource") != self.resource:
            raise AuthError("invalid_target")
        grant_type = data.get("grant_type")
        if grant_type not in ("authorization_code", "refresh_token"):
            raise AuthError("unsupported_grant_type")
        raw = data.get("code" if grant_type == "authorization_code" else "refresh_token", "")
        if not isinstance(raw, str) or not 32 <= len(raw) <= 256:
            raise AuthError("invalid_grant")
        now = int(time.time())
        result = None
        with self.connection() as db:
            if db.execute("SELECT 1 FROM clients WHERE client_id = ?", (client_id,)).fetchone() is None:
                raise AuthError("invalid_client", 401)
            if grant_type == "authorization_code":
                row = db.execute("SELECT * FROM codes WHERE code_hash = ?", (digest(raw),)).fetchone()
            else:
                row = db.execute("SELECT * FROM tokens WHERE token_hash = ? AND kind = 'refresh'", (digest(raw),)).fetchone()
            if row is None:
                raise AuthError("invalid_grant")
            grant = db.execute("SELECT * FROM grants WHERE grant_id = ?", (row["grant_id"],)).fetchone()
            if grant is None or grant["revoked"] or grant["expires"] <= now or row["expires"] <= now:
                raise AuthError("invalid_grant")
            if grant["client_id"] != client_id or grant["resource"] != data["resource"]:
                raise AuthError("invalid_grant")
            if grant_type == "authorization_code":
                verifier = data.get("code_verifier", "")
                if (
                    data.get("redirect_uri") != grant["redirect_uri"]
                    or not isinstance(verifier, str) or not PKCE_VERIFIER.fullmatch(verifier)
                    or not secrets.compare_digest(encoded(hashlib.sha256(verifier.encode("ascii")).digest()), row["challenge"])
                ):
                    raise AuthError("invalid_grant")
            elif data.get("redirect_uri", grant["redirect_uri"]) != grant["redirect_uri"]:
                raise AuthError("invalid_grant")
            if data.get("scope") is not None and parse_scopes(data["scope"]) != parse_scopes(grant["scopes"]):
                raise AuthError("invalid_scope")
            if row["used"]:
                db.execute("UPDATE grants SET revoked = 1 WHERE grant_id = ?", (grant["grant_id"],))
            else:
                if grant_type == "authorization_code":
                    db.execute("UPDATE codes SET used = 1 WHERE code_hash = ?", (digest(raw),))
                else:
                    db.execute("UPDATE tokens SET used = 1 WHERE token_hash = ?", (digest(raw),))
                result = self.issue_tokens(db, grant, now, initial=grant_type == "authorization_code")
            self.cleanup(db, now)
        if result is None:
            raise AuthError("invalid_grant")
        return result

    def authenticate(self, token):
        if not isinstance(token, str) or not 32 <= len(token) <= 256:
            raise AuthError("invalid_token", 401)
        now = int(time.time())
        with self.connection() as db:
            row = db.execute(
                "SELECT g.* FROM tokens t JOIN grants g ON g.grant_id = t.grant_id "
                "WHERE t.token_hash = ? AND t.kind = 'access' AND t.used = 0 "
                "AND t.expires > ? AND g.expires > ? AND g.revoked = 0",
                (digest(token), now, now),
            ).fetchone()
        if row is None or row["resource"] != self.resource:
            raise AuthError("invalid_token", 401)
        return {"client_id": row["client_id"], "grant_id": row["grant_id"], "scopes": parse_scopes(row["scopes"])}

    def grant_active(self, principal):
        if not isinstance(principal, dict):
            return False
        with self.connection() as db:
            row = db.execute(
                "SELECT scopes FROM grants WHERE grant_id = ? AND client_id = ? "
                "AND resource = ? AND expires > ? AND revoked = 0",
                (principal.get("grant_id"), principal.get("client_id"), self.resource, int(time.time())),
            ).fetchone()
        return row is not None and "hermes.read" in parse_scopes(row["scopes"])

    def revoke(self, data):
        client_id, token = data.get("client_id"), data.get("token")
        if not isinstance(client_id, str) or not isinstance(token, str) or not 1 <= len(token) <= 256:
            raise AuthError("invalid_request")
        if "client_secret" in data or "client_assertion" in data:
            raise AuthError("invalid_client", 401)
        with self.connection() as db:
            if db.execute("SELECT 1 FROM clients WHERE client_id = ?", (client_id,)).fetchone() is None:
                raise AuthError("invalid_client", 401)
            db.execute(
                "UPDATE grants SET revoked = 1 WHERE client_id = ? AND grant_id IN "
                "(SELECT grant_id FROM tokens WHERE token_hash = ?)", (client_id, digest(token)),
            )
