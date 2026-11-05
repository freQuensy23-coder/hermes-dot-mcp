import asyncio
import hashlib
import json
import os
import re
import sqlite3
import stat
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from weakref import WeakValueDictionary


HOME = Path(os.environ.get('HERMES_HOME', str(Path.home() / '.hermes'))).expanduser().resolve()
OWNER = os.environ.get('HERMES_DOT_OWNER_ID', '')
if re.fullmatch(r'[1-9][0-9]{0,18}', OWNER) is None:
    raise ValueError('HERMES_DOT_OWNER_ID must be an explicit positive Telegram user ID')
PROFILE = 'default'
SOCKET = HOME / 'hermes-dot-control.sock'
STATE = HOME / 'services' / 'hermes-dot-mcp' / 'control.db'
KEY = re.compile(rf'agent:main:telegram:dm:{OWNER}:([1-9][0-9]*)\Z')
SESSION_FIELDS = 's.id,s.session_key,s.thread_id,s.title,s.started_at,s.ended_at,s.last_activity_at,s.message_count'
MUTATIONS = frozenset({'messages_send', 'tasks_steer', 'tasks_stop', 'topics_create', 'topics_rename'})
LIVE = MUTATIONS | {'task_status'}


class BackendError(Exception):
    pass


def setting(settings, key, default=None):
    return settings.get(key, default) if isinstance(settings, dict) else getattr(settings, key, default)


def configuration(settings):
    home = Path(setting(settings, 'hermes_home', HOME)).absolute()
    socket_path = Path(setting(settings, 'socket_path', SOCKET)).absolute()
    state_path = Path(setting(settings, 'state_path', STATE)).absolute()
    if home != HOME or socket_path != SOCKET or setting(settings, 'owner_id', OWNER) != OWNER or setting(settings, 'profile', PROFILE) != PROFILE:
        raise BackendError('unsupported_home_owner_or_profile')
    if state_path != STATE:
        raise BackendError('unsupported_state_path')
    return home, socket_path, state_path


def key_ok(key, thread):
    match = KEY.fullmatch(key) if isinstance(key, str) else None
    return int(bool(match and str(thread) == match.group(1)))


def integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise BackendError('invalid_integer')
    return value


def string(value, maximum=512):
    if not isinstance(value, str) or not value or len(value) > maximum or '\x00' in value:
        raise BackendError('invalid_string')
    return value


def request_uuid(value):
    value = string(value, 36)
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        raise BackendError('request_id_must_be_uuid') from None
    if str(parsed) != value:
        raise BackendError('request_id_must_be_uuid')
    return value


def validate_args(name, args, tools):
    spec = next((tool['inputSchema'] for tool in tools if tool['name'] == name), None)
    if spec is None:
        raise BackendError('unknown_tool')
    if not isinstance(args, dict) or set(args) - set(spec['properties']) or any(k not in args for k in spec['required']):
        raise BackendError('invalid_arguments')
    for key, value in args.items():
        prop = spec['properties'][key]
        if prop['type'] == 'integer':
            integer(value, prop.get('minimum', 0), prop.get('maximum', 9223372036854775807))
        else:
            string(value, prop.get('maxLength', 512))
    if name in MUTATIONS:
        request_uuid(args['request_id'])
    if 'text' in args and args['text'].lstrip().startswith('/'):
        raise BackendError('slash_commands_forbidden')
    if 'title' in args and (not args['title'].strip() or any(ord(c) < 32 for c in args['title'])):
        raise BackendError('invalid_title')


def tool_specs():
    sid = {'type': 'string', 'minLength': 1, 'maxLength': 512, 'description': 'Exact scoped Hermes session ID; mutations fail if the topic was reset.'}
    rid = {'type': 'string', 'format': 'uuid', 'maxLength': 36, 'description': 'Stable UUID for this logical mutation; never change it to retry an uncertain outcome.'}
    limit = {'type': 'integer', 'minimum': 1, 'maximum': 100, 'default': 50}
    before = {'type': 'integer', 'minimum': 1, 'description': 'Exclusive real global message ID; omit for newest messages.'}
    text = {'type': 'string', 'minLength': 1, 'maxLength': 32000}
    title = {'type': 'string', 'minLength': 1, 'maxLength': 128}
    entries = [
        ('topics_list', 'List scoped known topic sessions with keyset pagination, not a Telegram-wide topic inventory.', {'limit': limit, 'cursor': sid}, [], 'hermes.read'),
        ('conversation_get', 'Read safe metadata for one scoped conversation.', {'session_id': sid}, ['session_id'], 'hermes.read'),
        ('messages_read', 'Read full user/assistant content backwards by real global integer message ID.', {'session_id': sid, 'before_id': before, 'limit': limit}, ['session_id'], 'hermes.read'),
        ('messages_search', 'Bounded literal substring search over the latest 5000 scoped user/assistant messages of one session.', {'session_id': sid, 'query': {'type': 'string', 'minLength': 1, 'maxLength': 256}, 'before_id': before, 'limit': limit}, ['session_id', 'query'], 'hermes.read'),
        ('events_poll', 'Read durable scoped user/assistant message events after a global integer cursor; replay the returned cursor, no acknowledgement side effects.', {'cursor': {'type': 'integer', 'minimum': 0}, 'limit': limit}, ['cursor'], 'hermes.read'),
        ('task_status', 'Inspect live exact-session agent activity, not stored transcript guesses.', {'session_id': sid}, ['session_id'], 'hermes.read'),
        ('messages_send', 'Accept dot-identified native plugin injection. Accepted means queued, never completed or delivered; slash commands forbidden.', {'session_id': sid, 'request_id': rid, 'text': text}, ['session_id', 'request_id', 'text'], 'hermes.write'),
        ('tasks_steer', 'Real mid-turn steer of the current exact-session agent and active children when supported; never queues a new turn.', {'session_id': sid, 'request_id': rid, 'text': text}, ['session_id', 'request_id', 'text'], 'hermes.control'),
        ('tasks_stop', 'Interrupt only the current exact session and its delegations; no chat-wide stop fallback. Acceptance is not proof processes have exited.', {'session_id': sid, 'request_id': rid}, ['session_id', 'request_id'], 'hermes.control'),
        ('topics_create', 'Create a fresh Telegram bot DM topic and native empty session from the fenced owner source. No history clone or configuration writes.', {'session_id': sid, 'request_id': rid, 'title': title}, ['session_id', 'request_id', 'title'], 'hermes.write'),
        ('topics_rename', 'Rename one bot topic and durably set its exact native session title; partial failures are not retried.', {'session_id': sid, 'request_id': rid, 'title': title}, ['session_id', 'request_id', 'title'], 'hermes.write'),
    ]
    result = []
    for name, description, properties, required, scope in entries:
        result.append({'name': name, 'description': description, 'inputSchema': {'type': 'object', 'properties': properties, 'required': required, 'additionalProperties': False}, '_meta': {'requiredScopes': [scope], 'securitySchemes': [{'type': 'oauth2', 'scopes': [scope]}]}, 'securitySchemes': [{'type': 'oauth2', 'scopes': [scope]}], 'annotations': {'readOnlyHint': name not in MUTATIONS, 'destructiveHint': name in {'messages_send', 'tasks_stop', 'topics_close', 'topics_rename', 'tasks_steer'}, 'idempotentHint': True, 'openWorldHint': name in MUTATIONS}})
    return result


TOOLS = tool_specs()


def secure_directory(path):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise BackendError('unsafe_state_directory')
    os.chmod(path, 0o700)


def secure_database(path):
    path = Path(path)
    secure_directory(path.parent)
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise BackendError('unsafe_state_file')
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)


class Receipts:
    def __init__(self, path, table):
        if table not in {'dot_backend_receipts', 'dot_bridge_receipts'}:
            raise BackendError('invalid_receipt_table')
        self.path = Path(path)
        self.table = table
        secure_database(self.path)
        with self.connect() as db:
            db.execute(f'CREATE TABLE IF NOT EXISTS {self.table} (request_id TEXT PRIMARY KEY, digest TEXT NOT NULL, state TEXT NOT NULL, result TEXT, updated_at REAL NOT NULL)')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            db.execute('PRAGMA synchronous=FULL')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def begin(self, name, args):
        fingerprint = hashlib.sha256(json.dumps([name, args], sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute(f'SELECT digest,state,result FROM {self.table} WHERE request_id=?', (args['request_id'],)).fetchone()
            if row:
                if row[0] != fingerprint:
                    raise BackendError('request_id_conflict')
                if row[2] is not None:
                    return json.loads(row[2])
                return {'ok': False, 'state': 'pending', 'outcome': 'unknown', 'request_id': args['request_id'], 'retry_safe': False, 'error': 'pending_or_unknown_outcome_never_automatically_retry'}
            db.execute(f'INSERT INTO {self.table} VALUES (?,?,?,?,?)', (args['request_id'], fingerprint, 'pending', None, time.time()))
        return None

    def finish(self, request_id, state, result):
        with self.connect() as db:
            db.execute(f'UPDATE {self.table} SET state=?,result=?,updated_at=? WHERE request_id=? AND state=?', (state, json.dumps(result, ensure_ascii=False), time.time(), request_id, 'pending'))


class Scope:
    def __init__(self, home=HOME):
        self.path = Path(home) / 'state.db'

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path.as_uri() + '?mode=ro', uri=True, timeout=3)
        db.row_factory = sqlite3.Row
        db.create_function('dot_key_ok', 2, key_ok, deterministic=True)
        db.execute('PRAGMA query_only=ON')
        deadline = time.monotonic() + 3
        db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        try:
            db.execute('BEGIN')
            yield db
        finally:
            db.close()

    def predicate(self, db):
        sql = f"s.source='telegram' AND s.chat_type IN ('dm','private') AND s.chat_id='{OWNER}' AND s.user_id='{OWNER}' AND s.profile_name='default' AND (s.transport_profile='default' OR s.transport_profile IS NULL) AND dot_key_ok(s.session_key,s.thread_id)=1"
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='telegram_dm_topic_bindings'")}
        if tables:
            columns = {row[1] for row in db.execute('PRAGMA table_info(telegram_dm_topic_bindings)')}
            if not {'profile_name', 'chat_id', 'thread_id', 'user_id', 'session_key', 'session_id'} <= columns:
                return sql + ' AND 0'
            sql += " AND NOT EXISTS (SELECT 1 FROM telegram_dm_topic_bindings b WHERE (((b.profile_name='default' OR b.profile_name IS NULL OR b.profile_name='') AND b.chat_id=s.chat_id AND b.thread_id=s.thread_id) OR b.session_id=s.id) AND COALESCE((b.profile_name='default' AND b.chat_id=s.chat_id AND b.thread_id=s.thread_id AND b.user_id=s.user_id AND b.session_key=s.session_key AND b.session_id=s.id),0)=0)"
        return sql

    def session(self, session_id):
        with self.connect() as db:
            row = db.execute(f'SELECT {SESSION_FIELDS} FROM sessions s WHERE {self.predicate(db)} AND s.id=?', (session_id,)).fetchone()
            if row is None:
                raise BackendError('session_not_found_or_out_of_scope')
            return dict(row)

    def read(self, name, args):
        with self.connect() as db:
            scope = self.predicate(db)
            limit = args.get('limit', 50)
            if name == 'topics_list':
                rows = db.execute(f'SELECT {SESSION_FIELDS} FROM sessions s WHERE {scope} AND (? IS NULL OR s.id < ?) ORDER BY s.id DESC LIMIT ?', (args.get('cursor'), args.get('cursor'), limit + 1)).fetchall()
                page = [dict(row) for row in rows[:limit]]
                return {'topics': page, 'has_more': len(rows) > limit, 'next_cursor': page[-1]['id'] if page and len(rows) > limit else None}
            if name == 'events_poll':
                cursor = args['cursor']
                high = db.execute('SELECT COALESCE(MAX(id),0) FROM messages').fetchone()[0]
                rows = db.execute(f"SELECT m.id,s.session_key,m.session_id,m.role,m.content,m.timestamp FROM messages m JOIN sessions s ON s.id=m.session_id WHERE {scope} AND m.role IN ('user','assistant') AND m.content IS NOT NULL AND m.id>? AND m.id<=? ORDER BY m.id LIMIT ?", (cursor, high, limit + 1)).fetchall()
                page = [dict(row) for row in rows[:limit]]
                for event in page:
                    if event['role'] == 'user' and isinstance(event['content'], str) and re.match(r'\[dot request [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\]\n', event['content']):
                        event['from_dot'] = True
                more = len(rows) > limit
                next_cursor = page[-1]['id'] if more else max(cursor, high)
                return {'events': page, 'has_more': more, 'cursor': next_cursor, 'next_cursor': next_cursor}
            row = db.execute(f'SELECT {SESSION_FIELDS} FROM sessions s WHERE {scope} AND s.id=?', (args['session_id'],)).fetchone()
            if row is None:
                raise BackendError('session_not_found_or_out_of_scope')
            if name == 'conversation_get':
                return {'conversation': dict(row)}
            params = [args['session_id'], args.get('before_id', 9223372036854775807)]
            select = f"SELECT m.id,m.session_id,m.role,m.content,m.timestamp FROM messages m JOIN sessions s ON s.id=m.session_id WHERE {scope} AND s.id=? AND m.id<? AND m.role IN ('user','assistant') AND m.content IS NOT NULL ORDER BY m.id DESC"
            if name == 'messages_search':
                rows = db.execute(f'SELECT * FROM ({select} LIMIT 5000) WHERE instr(lower(content),lower(?))>0 ORDER BY id DESC LIMIT ?', (*params, args['query'], limit + 1)).fetchall()
            else:
                rows = db.execute(select + ' LIMIT ?', (*params, limit + 1)).fetchall()
            page = [dict(item) for item in rows[:limit]]
            return {'messages': page, 'has_more': len(rows) > limit, 'next_before_id': page[-1]['id'] if page and len(rows) > limit else None, **({'search_window': 5000, 'bounded': True} if name == 'messages_search' else {})}


class Backend:
    tools = TOOLS

    def __init__(self, settings):
        self.home, self.socket_path, self.state_path = configuration(settings)
        self.scope = Scope(self.home)
        self.receipts = Receipts(self.state_path, 'dot_backend_receipts')
        self._locks = WeakValueDictionary()

    async def call(self, name, args):
        validate_args(name, args, self.tools)
        if name not in LIVE:
            return await asyncio.to_thread(self.scope.read, name, args)
        mutation = name in MUTATIONS
        lock = self._locks.setdefault(args.get('request_id', args['session_id']), asyncio.Lock())
        async with lock:
            if mutation:
                previous = await asyncio.to_thread(self.receipts.begin, name, args)
                if previous is not None:
                    return previous
            try:
                selected = await asyncio.to_thread(self.scope.session, args['session_id'])
                payload = {'name': name, 'args': args, 'session_key': selected['session_key']}
                result = await self._bridge(payload)
            except asyncio.CancelledError:
                raise
            except BackendError as exc:
                result = {'ok': False, 'state': 'error', 'error': str(exc), 'outcome': 'unknown' if mutation else 'unavailable', 'retry_safe': False}
            except Exception:
                result = {'ok': False, 'state': 'error', 'error': 'bridge_unavailable_or_invalid_response', 'outcome': 'unknown' if mutation else 'unavailable', 'retry_safe': False}
            if mutation:
                result['request_id'] = args['request_id']
                await asyncio.to_thread(self.receipts.finish, args['request_id'], 'complete' if result.get('ok') else 'error', result)
            return result

    async def _bridge(self, payload):
        import aiohttp
        info = self.socket_path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise BackendError('unsafe_bridge_socket')
        wire = json.dumps(payload, ensure_ascii=False).encode()
        if len(wire) > 65536:
            raise BackendError('request_too_large')
        connector = aiohttp.UnixConnector(path=str(self.socket_path))
        async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=35), trust_env=False) as client:
            async with client.post('http://localhost/call', data=wire, headers={'Content-Type': 'application/json'}, allow_redirects=False) as response:
                if response.status != 200:
                    raise BackendError('bridge_rejected_request')
                raw = bytearray()
                async for chunk in response.content.iter_chunked(65536):
                    raw.extend(chunk)
                    if len(raw) > 1048576:
                        raise BackendError('bridge_response_too_large')
                result = json.loads(raw)
                if not isinstance(result, dict) or type(result.get('ok')) is not bool:
                    raise BackendError('invalid_bridge_response')
                return result
