const paths = new Set(['/healthz', '/mcp', '/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp', '/.well-known/oauth-authorization-server', '/register', '/authorize', '/token', '/revoke']);
const requestHeaders = new Set(['content-type', 'accept', 'authorization', 'origin', 'mcp-protocol-version', 'cookie']);
const responseHeaders = new Set(['content-type', 'www-authenticate', 'set-cookie', 'location', 'cache-control', 'pragma', 'x-content-type-options', 'referrer-policy', 'x-frame-options', 'content-security-policy', 'strict-transport-security', 'allow', 'retry-after']);

function equal(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return mismatch === 0;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/internal/bridge') {
      if (!env.BRIDGE_TOKEN || !equal(request.headers.get('Authorization'), `Bearer ${env.BRIDGE_TOKEN}`)) return new Response('Unauthorized', {status: 401});
      if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') return new Response('Upgrade required', {status: 426});
    } else if (!paths.has(url.pathname)) {
      return new Response('Not found', {status: 404});
    }
    const object = env.RELAY.get(env.RELAY.idFromName('owner'));
    return object.fetch(request);
  }
};

export class OwnerRelay {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
    this.socket = ctx.getWebSockets('bridge')[0] || null;
    this.pending = new Map();
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair('{"type":"heartbeat"}', '{"type":"heartbeat"}'));
  }

  rejectPending() {
    for (const request of this.pending.values()) {
      clearTimeout(request.timer);
      request.resolve(new Response('Private bridge unavailable', {status: 503}));
    }
    this.pending.clear();
  }

  webSocketMessage(server, data) {
    if (this.socket !== server || typeof data !== 'string' || data.length > 12000000) return;
    let result;
    try { result = JSON.parse(data); } catch { return; }
    const pending = this.pending.get(result.id);
    if (!pending) return;
    this.pending.delete(result.id);
    clearTimeout(pending.timer);
    try {
      if (!Number.isInteger(result.status) || result.status < 200 || result.status > 599 || !Array.isArray(result.headers) || typeof result.body !== 'string') throw new Error();
      const bytes = Uint8Array.from(atob(result.body), c => c.charCodeAt(0));
      const headers = new Headers();
      for (const [key, value] of result.headers) if (responseHeaders.has(key.toLowerCase())) headers.append(key, value);
      headers.set('Cache-Control', 'no-store');
      const empty = pending.method === 'HEAD' || result.status === 204 || result.status === 304;
      pending.resolve(new Response(empty ? null : bytes, {status: result.status, headers}));
    } catch {
      pending.resolve(new Response('Invalid bridge response', {status: 502}));
    }
  }

  webSocketClose(server) {
    if (this.socket === server) { this.socket = null; this.rejectPending(); }
    server.close();
  }

  webSocketError(server) {
    if (this.socket === server) { this.socket = null; this.rejectPending(); }
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/internal/bridge') {
      if (!this.env.BRIDGE_TOKEN || !equal(request.headers.get('Authorization'), `Bearer ${this.env.BRIDGE_TOKEN}`)) return new Response('Unauthorized', {status: 401});
      const pair = new WebSocketPair();
      const client = pair[0];
      const server = pair[1];
      if (this.socket) {
        this.socket.close(1012, 'Bridge replaced');
        this.rejectPending();
      }
      this.socket = server;
      this.ctx.acceptWebSocket(server, ['bridge']);
      return new Response(null, {status: 101, webSocket: client});
    }
    if (!paths.has(url.pathname)) return new Response('Not found', {status: 404});
    if (new TextEncoder().encode(url.pathname + url.search).byteLength > 8192) return new Response('URI too long', {status: 414});
    const headers = [...request.headers].filter(([name]) => requestHeaders.has(name.toLowerCase()));
    let headerBytes = 0;
    for (const [name, value] of headers) {
      const bytes = new TextEncoder().encode(name + ': ' + value).byteLength;
      if (bytes > 8192) return new Response('Header too large', {status: 431});
      headerBytes += bytes;
    }
    if (headerBytes > 16384) return new Response('Headers too large', {status: 431});
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN) return new Response('Private bridge unavailable', {status: 503});
    if (this.pending.size >= 32) return new Response('Busy', {status: 429, headers: {'Retry-After': '2'}});
    const reader = request.body?.getReader();
    const chunks = [];
    let size = 0;
    if (reader) {
      while (true) {
        const {value, done} = await reader.read();
        if (done) break;
        size += value.length;
        if (size > 65536) { await reader.cancel(); return new Response('Request too large', {status: 413}); }
        chunks.push(value);
      }
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    const id = crypto.randomUUID();
    const body = JSON.stringify({id, method: request.method, path: url.pathname + url.search, headers, body: btoa(binary)});
    if (new TextEncoder().encode(body).byteLength > 131072) return new Response('Request envelope too large', {status: 413});
    return await new Promise(resolve => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        resolve(new Response('Private bridge deadline exceeded', {status: 504}));
      }, 65000);
      this.pending.set(id, {resolve, timer, method: request.method});
      try { this.socket.send(body); } catch {
        clearTimeout(timer);
        this.pending.delete(id);
        resolve(new Response('Private bridge unavailable', {status: 503}));
      }
    });
  }
}
