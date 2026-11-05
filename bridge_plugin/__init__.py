import asyncio
import importlib.util
import inspect
import json
import logging
import os
import socket
import stat
import struct
import sys
from pathlib import Path
from weakref import WeakValueDictionary


ROOT = Path(os.environ['HERMES_DOT_SOURCE_ROOT']).expanduser().resolve()
MODULE_NAME = '_hermes_dot_bridge_backend'
if MODULE_NAME not in sys.modules:
    specification = importlib.util.spec_from_file_location(MODULE_NAME, ROOT / 'backend.py')
    module = importlib.util.module_from_spec(specification)
    sys.modules[MODULE_NAME] = module
    specification.loader.exec_module(module)
shared = sys.modules[MODULE_NAME]
logger = logging.getLogger('hermes-dot-control')


class Bridge:
    def __init__(self, ctx, native, adapter):
        self.ctx = ctx
        self.native = native
        self.adapter = adapter
        self.loop = asyncio.get_running_loop()
        self.tasks = set()
        self.runner = None
        self.web_runner = None
        self.socket_identity = None
        self.closed = False
        self.receipts = None
        self.locks = WeakValueDictionary()

    def read_settings(self):
        manager_home = Path(self.ctx._manager.home_path).resolve()
        if manager_home != shared.HOME:
            raise shared.BackendError('plugin_home_mismatch')
        path = manager_home / 'services' / 'hermes-dot-mcp' / 'config.json'
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise shared.BackendError('unsafe_bridge_configuration')
            with os.fdopen(descriptor, 'rb', closefd=False) as stream:
                data = stream.read(65537)
        finally:
            os.close(descriptor)
        if len(data) > 65536:
            raise shared.BackendError('bridge_configuration_too_large')
        config = json.loads(data)
        settings = config.get('backend') if isinstance(config, dict) else None
        if not isinstance(settings, dict):
            raise shared.BackendError('backend_configuration_required')
        return shared.configuration(settings)

    def spawn(self, coroutine):
        task = self.loop.create_task(coroutine)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        task.add_done_callback(self.task_finished)
        return task

    @staticmethod
    def task_finished(task):
        if not task.cancelled() and task.exception() is not None:
            logger.error('Dot bridge background operation failed; no automatic retry')

    def validate_runtime(self):
        from hermes_constants import get_hermes_home
        manager = self.ctx._manager
        if Path(manager.home_path).resolve() != shared.HOME or Path(get_hermes_home()).resolve() != shared.HOME:
            raise shared.BackendError('home_mismatch')
        registered = getattr(manager, '_gateway_message_injector', None)
        if not isinstance(registered, tuple) or len(registered) != 2 or not callable(registered[1]):
            raise shared.BackendError('live_runner_unavailable')
        runner = registered[0]
        if self.runner is not None and runner is not self.runner:
            raise shared.BackendError('runner_replaced')
        if not getattr(runner, '_running', False) or getattr(runner, '_draining', False) or getattr(runner, '_gateway_loop', None) is not self.loop:
            raise shared.BackendError('runner_not_accepting')
        store = getattr(runner, 'session_store', None)
        routing_home = getattr(store, '_routing_home', None)
        if routing_home is None or Path(routing_home).resolve() != shared.HOME:
            raise shared.BackendError('runner_home_mismatch')
        if getattr(self.adapter, '_owner_profile', None) not in (None, 'default'):
            raise shared.BackendError('adapter_profile_mismatch')
        if getattr(manager, '_cli_ref', None) is not None:
            raise shared.BackendError('cli_injection_forbidden')
        if self.ctx.plugin_id != 'hermes-dot-control':
            raise shared.BackendError('plugin_id_mismatch')
        return runner

    async def start(self):
        from aiohttp import web
        _, _, state_path = self.read_settings()
        for attempt in range(480):
            if self.closed:
                return
            try:
                self.runner = self.validate_runtime()
                break
            except shared.BackendError as error:
                if str(error) not in {'live_runner_unavailable', 'runner_not_accepting'} or attempt == 479:
                    raise
                await asyncio.sleep(0.25)
        home_info = shared.HOME.lstat()
        if not stat.S_ISDIR(home_info.st_mode) or home_info.st_uid != os.getuid() or stat.S_IMODE(home_info.st_mode) & 0o077:
            raise shared.BackendError('home_directory_must_be_private')
        for attempt in range(40):
            if not shared.SOCKET.exists() and not shared.SOCKET.is_symlink():
                break
            if attempt == 39:
                raise shared.BackendError('socket_already_exists_no_automatic_unlink')
            await asyncio.sleep(0.1)
        self.receipts = shared.Receipts(state_path, 'dot_bridge_receipts')
        application = web.Application(client_max_size=65536)
        application.router.add_post('/call', self.handle)
        self.web_runner = web.AppRunner(application, access_log=None, shutdown_timeout=3)
        await self.web_runner.setup()
        site = web.UnixSite(self.web_runner, str(shared.SOCKET), shutdown_timeout=3)
        try:
            await site.start()
            info = shared.SOCKET.lstat()
            self.socket_identity = (info.st_dev, info.st_ino)
            os.chmod(shared.SOCKET, 0o600)
        except BaseException:
            await self.close()
            raise

    def unload(self):
        self.closed = True
        if self.loop.is_closed():
            return
        try:
            current = asyncio.get_running_loop()
        except RuntimeError:
            current = None
        if current is self.loop:
            self.loop.create_task(self.close())
        else:
            asyncio.run_coroutine_threadsafe(self.close(), self.loop)

    async def close(self):
        self.closed = True
        current = asyncio.current_task()
        pending = [task for task in list(self.tasks) if task is not current and not task.done()]
        for task in pending:
            task.cancel()
        if self.web_runner is not None:
            runner, self.web_runner = self.web_runner, None
            await runner.cleanup()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        if self.socket_identity is not None:
            try:
                info = shared.SOCKET.lstat()
                if (info.st_dev, info.st_ino) == self.socket_identity and stat.S_ISSOCK(info.st_mode):
                    shared.SOCKET.unlink()
            except FileNotFoundError:
                pass
            self.socket_identity = None

    @staticmethod
    def peer_allowed(request):
        transport = request.transport
        peer = transport.get_extra_info('socket') if transport is not None else None
        if peer is None or not hasattr(socket, 'SO_PEERCRED'):
            return False
        try:
            _, uid, _ = struct.unpack('3i', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
            return uid == os.getuid()
        except (OSError, ValueError, struct.error):
            return False

    async def handle(self, request):
        from aiohttp import web
        if self.closed or not self.peer_allowed(request):
            return web.json_response({'ok': False, 'error': 'peer_denied'}, status=403)
        try:
            if request.content_type != 'application/json':
                raise shared.BackendError('json_required')
            wire = await request.read()
            if len(wire) > 65536:
                raise shared.BackendError('request_too_large')
            payload = json.loads(wire)
            if not isinstance(payload, dict) or set(payload) != {'name', 'args', 'session_key'}:
                raise shared.BackendError('invalid_envelope')
            name, args, session_key = payload['name'], payload['args'], payload['session_key']
            shared.validate_args(name, args, shared.TOOLS)
            if name not in shared.LIVE or not isinstance(session_key, str) or shared.KEY.fullmatch(session_key) is None:
                raise shared.BackendError('unsupported_operation')
            lock = self.locks.setdefault(args['session_id'], asyncio.Lock())
            async with lock:
                result = await self.invoke(name, args, session_key)
            return web.json_response(result)
        except asyncio.CancelledError:
            raise
        except shared.BackendError as error:
            return web.json_response({'ok': False, 'state': 'error', 'error': str(error), 'retry_safe': False})
        except Exception:
            return web.json_response({'ok': False, 'state': 'error', 'error': 'bridge_operation_failed', 'outcome': 'unknown', 'retry_safe': False})

    async def resolve(self, session_id, key):
        runner = self.validate_runtime()
        row = await asyncio.to_thread(shared.Scope().session, session_id)
        if row['session_key'] != key:
            raise shared.BackendError('session_fence_mismatch')
        entry = await runner.async_session_store.lookup_by_session_key(key)
        if entry is None or entry.session_id != session_id or entry.session_key != key:
            raise shared.BackendError('session_reset_or_not_current')
        if getattr(entry, 'transport_profile', None) not in (None, 'default'):
            raise shared.BackendError('transport_profile_mismatch')
        source = runner._restored_source(entry)
        self.validate_source(source, key)
        if runner._delivery_adapter_for(source) is not self.adapter:
            raise shared.BackendError('adapter_mismatch')
        if not runner._is_user_authorized_for_source(source, allow_adapter_delegation=False):
            raise shared.BackendError('native_authorization_denied')
        self.recheck(entry, session_id, key)
        return entry, source

    def validate_source(self, source, key):
        from gateway.session_identity import identity_of
        if source is None or getattr(getattr(source, 'platform', None), 'value', None) != 'telegram':
            raise shared.BackendError('source_platform_mismatch')
        if source.chat_type not in ('dm', 'private') or str(source.chat_id) != shared.OWNER or str(source.user_id) != shared.OWNER or not shared.key_ok(key, source.thread_id):
            raise shared.BackendError('source_owner_or_thread_mismatch')
        if getattr(source, 'profile', None) not in (None, 'default'):
            raise shared.BackendError('source_profile_mismatch')
        identity = identity_of(source)
        if identity is None or identity.runtime_profile != 'default' or identity.transport_profile != 'default' or Path(identity.runtime_home).resolve() != shared.HOME or Path(identity.authorization_home).resolve() != shared.HOME:
            raise shared.BackendError('source_identity_mismatch')
        if self.runner._session_key_for_source(source) != key:
            raise shared.BackendError('derived_session_key_mismatch')

    def recheck(self, entry, session_id, key):
        self.validate_runtime()
        current = self.runner.session_store.lookup_by_session_key(key)
        if current is None or current.session_id != session_id or entry.session_id != session_id:
            raise shared.BackendError('session_fence_changed')

    def current_agent(self, key, session_id, require=False):
        from gateway.run import _AGENT_PENDING_SENTINEL
        state = self.runner._peek_session_state(key)
        agent = state.turn.agent if state is not None else None
        if agent is _AGENT_PENDING_SENTINEL:
            agent = None
        if agent is not None and str(getattr(agent, 'session_id', '') or '') != session_id:
            raise shared.BackendError('agent_not_ready_or_session_mismatch')
        if require and agent is None:
            raise shared.BackendError('no_running_agent')
        return agent

    async def invoke(self, name, args, key):
        mutation = name in shared.MUTATIONS
        if mutation:
            previous = await asyncio.to_thread(self.receipts.begin, name, args)
            if previous is not None:
                return previous
        try:
            entry, source = await self.resolve(args['session_id'], key)
            result = await self.operation(name, args, key, entry, source)
        except asyncio.CancelledError:
            raise
        except shared.BackendError as error:
            result = {'ok': False, 'state': 'error', 'error': str(error), 'outcome': 'unknown' if mutation else 'unavailable', 'retry_safe': False}
        except Exception:
            result = {'ok': False, 'state': 'error', 'error': 'native_operation_failed', 'outcome': 'unknown' if mutation else 'unavailable', 'retry_safe': False}
        if mutation:
            result['request_id'] = args['request_id']
            await asyncio.to_thread(self.receipts.finish, args['request_id'], 'complete' if result.get('ok') else 'error', result)
        return result

    async def operation(self, name, args, key, entry, source):
        session_id = args['session_id']
        self.recheck(entry, session_id, key)
        if name == 'task_status':
            from gateway.run import _AGENT_PENDING_SENTINEL
            from tools.async_delegation import has_live_for_session
            state = self.runner._peek_session_state(key)
            starting = state is not None and state.turn.agent is _AGENT_PENDING_SENTINEL
            agent = self.current_agent(key, session_id)
            activity = agent.get_activity_summary() if agent is not None else None
            if isinstance(activity, dict):
                allowed = {'last_activity_at', 'last_activity_description', 'last_activity_provenance', 'seconds_since_activity', 'idle_seconds', 'description', 'provenance', 'current_tool', 'api_call_count', 'max_iterations', 'budget_used', 'budget_max'}
                activity = {field: value for field, value in activity.items() if field in allowed and isinstance(value, (str, int, float, bool, type(None)))}
            else:
                activity = None
            return {'ok': True, 'session_id': session_id, 'running': starting or agent is not None, 'starting': starting, 'activity': activity, 'live_delegations': bool(has_live_for_session(parent_session_id=session_id))}
        if name == 'messages_send':
            return await self.send_fenced(args, key, entry)
        if name == 'tasks_steer':
            agent = self.current_agent(key, session_id, require=True)
            text = '[dot steer]\n' + args['text']
            helper = getattr(self.runner, '_steer_running_agent_and_subagents', None)
            if helper is None:
                helper = getattr(self.runner, '_steer_running_agent', None)
            if callable(helper) and not inspect.iscoroutinefunction(helper):
                inspect.signature(helper).bind(agent, text)
                accepted = bool(helper(agent, text))
                children_supported = True
            else:
                steer = getattr(agent, 'steer', None)
                if not callable(steer) or inspect.iscoroutinefunction(steer):
                    raise shared.BackendError('steer_unsupported')
                inspect.signature(steer).bind(text)
                accepted = bool(steer(text))
                children_supported = False
                child_helper = getattr(self.runner, '_steer_active_subagents', None)
                if callable(child_helper) and not inspect.iscoroutinefunction(child_helper):
                    inspect.signature(child_helper).bind(agent, text)
                    accepted = bool(child_helper(agent, text)) or accepted
                    children_supported = True
            return {'ok': accepted, 'state': 'accepted' if accepted else 'error', 'accepted': accepted, 'completed': False, 'subagent_fanout_supported': children_supported, 'session_id': session_id}
        if name == 'tasks_stop':
            from gateway.run import _INTERRUPT_REASON_STOP
            from tools.async_delegation import interrupt_for_session, list_async_delegations
            agent = self.current_agent(key, session_id)
            for delegation in list_async_delegations():
                if delegation.get('session_key') == key and delegation.get('parent_session_id') != session_id and delegation.get('status') in {'running', 'stalling', 'queued', 'pending', 'finalizing'}:
                    raise shared.BackendError('stop_refused_foreign_generation_delegation')
            inspect.signature(self.runner._interrupt_and_clear_session).bind(key, source, interrupt_reason=_INTERRUPT_REASON_STOP, invalidation_reason='dot_stop')
            self.recheck(entry, session_id, key)
            count = interrupt_for_session(parent_session_id=session_id, reason='dot_stop')
            await self.runner._interrupt_and_clear_session(key, source, interrupt_reason=_INTERRUPT_REASON_STOP, invalidation_reason='dot_stop')
            return {'ok': True, 'state': 'accepted', 'accepted': True, 'completed': False, 'session_id': session_id, 'agent_interrupt_requested': agent is not None, 'delegations_interrupt_requested': count}
        bot = getattr(self.adapter, '_bot', None)
        if bot is None or getattr(self.native, 'bot', None) is not bot:
            raise shared.BackendError('native_bot_unavailable')
        if name == 'topics_create':
            return await self.create_topic(args, entry, source, key)
        if name == 'topics_rename':
            db = getattr(self.runner, '_session_db', None)
            if db is None or not callable(getattr(db, 'set_session_title', None)) or not callable(getattr(db, 'get_session_title', None)):
                raise shared.BackendError('native_title_store_unavailable')
            result = await bot.edit_forum_topic(chat_id=int(shared.OWNER), message_thread_id=int(source.thread_id), name=args['title'])
            if result is not True:
                raise shared.BackendError('bot_rename_not_confirmed')
            self.recheck(entry, session_id, key)
            await db.set_session_title(session_id, args['title'])
            if await db.get_session_title(session_id) != args['title']:
                raise shared.BackendError('local_title_verification_failed')
            await self.resolve(session_id, key)
            return {'ok': True, 'state': 'complete', 'session_id': session_id, 'title': args['title'], 'bot_acknowledged': True, 'local_title_verified': True, 'remote_readback_supported': False}
        raise shared.BackendError('unsupported_operation')

    async def send_fenced(self, args, key, entry):
        if not self.ctx._gateway_injection_allowed():
            raise shared.BackendError('injection_consent_required')
        self.recheck(entry, args['session_id'], key)
        content = '[dot request ' + args['request_id'] + ']\n' + args['text']
        accepted = await self.dispatch_fenced(args['session_id'], key, content, self.ctx.plugin_id)
        if not accepted:
            raise shared.BackendError('injection_not_admitted')
        return {'ok': True, 'state': 'accepted', 'accepted': True, 'completed': False, 'delivery': 'admitted', 'session_id': args['session_id'], 'request_id': args['request_id'], 'origin': 'dot'}

    async def dispatch_fenced(self, session_id, key, content, plugin_id):
        from gateway.platforms.base import MessageEvent, MessageType
        from gateway.session_identity import replace_source
        entry, source = await self.resolve(session_id, key)
        self.recheck(entry, session_id, key)
        event = MessageEvent(text=content, message_type=MessageType.TEXT, source=replace_source(source), internal=True, allow_gateway_control=False, metadata={'hermes_plugin_id': plugin_id, 'hermes_plugin_injection': True, 'gateway_session_key': key, 'gateway_session_id': session_id, 'gateway_session_strict': True, 'dot_origin': True})
        await self.adapter.handle_message(event)
        return bool(event._gateway_accepted)

    async def create_topic(self, args, entry, source, key):
        from gateway.session_identity import replace_source
        session_id = args['session_id']
        creator = getattr(self.adapter, 'create_handoff_thread', None)
        if not callable(creator):
            raise shared.BackendError('topic_creation_unsupported')
        db = getattr(self.runner, '_session_db', None)
        if db is None or not callable(getattr(db, 'set_session_title', None)):
            raise shared.BackendError('native_title_store_unavailable')
        store = self.runner.async_session_store
        inspect.signature(self.runner.session_store.get_or_create_session).bind(source, touch_activity=False)
        inspect.signature(self.runner._record_telegram_topic_binding).bind(source, entry)
        self.recheck(entry, session_id, key)
        thread_id = await creator(shared.OWNER, args['title'])
        if not isinstance(thread_id, str) or not thread_id.isascii() or not thread_id.isdecimal() or str(int(thread_id)) != thread_id or int(thread_id) <= 0:
            raise shared.BackendError('topic_creation_unknown_outcome')
        self.recheck(entry, session_id, key)
        destination = replace_source(self.runner._restored_source(entry), thread_id=str(thread_id))
        destination_key = 'agent:main:telegram:dm:' + shared.OWNER + ':' + thread_id
        self.validate_source(destination, destination_key)
        if await store.lookup_by_session_key(destination_key) is not None:
            raise shared.BackendError('created_topic_already_bound_no_overwrite')
        created = await store.get_or_create_session(destination, touch_activity=False)
        if created.session_key != destination_key:
            raise shared.BackendError('new_session_key_mismatch')
        await asyncio.to_thread(self.runner._record_telegram_topic_binding, destination, created)
        await db.set_session_title(created.session_id, args['title'])
        if await db.get_session_title(created.session_id) != args['title']:
            raise shared.BackendError('new_session_title_verification_failed')
        verified, _ = await self.resolve(created.session_id, destination_key)
        return {'ok': True, 'state': 'complete', 'session_id': verified.session_id, 'session_key': destination_key, 'thread_id': thread_id, 'title': args['title'], 'native_binding_verified': True}


def register(ctx):
    bridges = []

    def factory(native, adapter):
        if getattr(adapter, '_owner_profile', None) not in (None, 'default'):
            return
        previous = list(bridges)
        bridges.clear()
        bridge = Bridge(ctx, native, adapter)
        bridges.append(bridge)

        async def replace_bridge():
            for old in previous:
                await old.close()
            await bridge.start()

        bridge.spawn(replace_bridge())

    def unload():
        for bridge in bridges:
            bridge.unload()
        bridges.clear()

    ctx.register_platform_handler('telegram', factory)
    ctx.on_unload(unload)
    registered = getattr(ctx._manager, '_gateway_message_injector', None)
    if isinstance(registered, tuple) and len(registered) == 2:
        runner = registered[0]
        loop = getattr(runner, '_gateway_loop', None)
        from gateway.config import Platform
        adapter = getattr(runner, 'adapters', {}).get(Platform.TELEGRAM)
        native = getattr(adapter, '_plugin_handler_native', None)
        if loop is not None and not loop.is_closed() and adapter is not None and native is not None:
            loop.call_soon_threadsafe(factory, native, adapter)

