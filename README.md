# Hermes Dot MCP

An owner-only MCP server connecting OpenAI dots / ChatGPT to a running Hermes Telegram gateway.

It exposes 11 tools: topic listing, conversation metadata, message reads/search, durable event polling, task status, message injection, live steering/stopping, and topic creation/rename. Optional MCP Events lets a client subscribe to new messages instead of repeatedly asking for updates.

## Architecture

ChatGPT connects over HTTPS with OAuth. The HTTP service reads scoped Hermes transcripts through read-only SQLite. Mutations pass through a same-user Unix socket to the native `hermes-dot-control` plugin in the live gateway. An optional Cloudflare Worker relays requests over an authenticated outbound WebSocket, avoiding an inbound server port.

This is a source export of a single-owner deployment. Personal identifiers and deployment paths have been replaced with required startup environment variables; production credentials, databases, transcripts and operational evidence are not included. The exported portability changes have not been exercised against another installation. Private Hermes APIs require compatibility review before deployment or upgrades.

## Connect an existing server to dot

Open [ChatGPT Plugins](https://chatgpt.com/plugins), select **Add custom MCP server**, enter your HTTPS `/mcp` URL and choose OAuth. Create/install the plugin, sign in on the server's owner-authorization page, and grant the permissions you need. Enable the plugin for your dot.

OAuth client registration is automatic; the login password is chosen by the server operator. No bearer token belongs in the MCP URL.

Start with “Use Hermes to list my topics.” Events are optional: “When Hermes replies in this topic, tell me the result.” A subscription must be created by the client; enabling the plugin does not start monitoring automatically.

## Self-hosting

Use Linux and Python 3.11+, a compatible running Hermes Telegram gateway, and Telegram private-chat Threaded Mode already enabled for the bot. Install `requirements.txt` in a dedicated environment. This repository does not change bot or gateway settings automatically.

Set `HERMES_HOME` to the absolute default-profile Hermes home, `HERMES_DOT_OWNER_ID` to the explicit positive Telegram owner ID, and `HERMES_DOT_SOURCE_ROOT` to the absolute repository directory. Both the HTTP process and the Hermes gateway process must receive the same values. The backend refuses to import without an explicit owner ID. Only the `default` profile is supported.

Create a private `services/hermes-dot-mcp/` directory under that home with mode 0700. Adapt `config.example.json`: all example absolute paths must be replaced. Store the configuration with mode 0600. Generate a unique owner password and a scrypt hash in the supported `scrypt$N$r$p$salt$hash` format; `N=32768`, `r=8`, `p=1`, a random 32-byte salt and a 64-byte digest are supported. Salt/digest may be hex. Do not use a published example password.

Stage `bridge_plugin/__init__.py` and `plugin.yaml` into `$HERMES_HOME/plugins/hermes-dot-control/`. Enable the plugin through the native Hermes CLI. Grant `plugins.entries.hermes-dot-control.allow_gateway_injection` only with the owner's consent. The plugin reads `$HERMES_HOME/services/hermes-dot-mcp/config.json`; its fixed socket and receipt paths must match the example layout. The Hermes home itself must be owned by the process user and private (0700).

Run `python server.py --config /absolute/path/to/config.json`. It binds only to loopback. Supply a trusted HTTPS reverse proxy preserving Host, Authorization, cookies and OAuth response headers, or deploy the optional Worker from `edge/` using Wrangler.

For the Worker route, generate a separate random bridge token. Put it in the Worker secret `BRIDGE_TOKEN` and in a private JSON file as `bridge_token`; point `relay_credentials` at that file. Run `python relay.py --config /absolute/path/to/config.json`. Never reuse the owner login password as the bridge token. Keep the relay, OAuth and event databases outside the checkout and maintain private backups.

## Authorization and boundaries

Permissions are independent: `hermes.read` for reads/status/events; `hermes.write` for message injection and topic creation/rename; `hermes.control` for steering/stopping; `offline_access` for refresh-token access. OAuth uses S256 PKCE, resource-bound grants, exact ChatGPT callback validation, rotating refresh tokens and revocation.

Every selection is fenced to one owner, a private Telegram chat, the explicit default profile and exact topic/session identity. Reads expose user/assistant messages, not internal tool/reasoning records. There are no arbitrary filesystem/shell/configuration/approval tools, broad chat targets, session deletion or personal Telegram-account access. Giving a client permission to send natural-language tasks still lets it ask Hermes to use Hermes's own capabilities; use the connected agent's permission controls accordingly.

Mutations require a canonical UUID `request_id` and exact `session_id`. Reusing the UUID with changed arguments is rejected. An uncertain result must not be retried with a new UUID. Message acceptance is not model-turn completion; stop acceptance does not prove every subprocess exited.

## Events and limits

The server advertises `events` and implements `events/list`, `events/subscribe`, `events/unsubscribe`. New-message subscriptions support an optional `session_key` filter, signed callback verification, Standard Webhooks HMAC signatures, durable pending deliveries, finite TTL, bounded retries and grant rechecks. Callbacks require public HTTPS and connection-time address validation; redirects and environment proxies are disabled. There is no protocol replay cursor.

Dot-injected user rows are excluded from notifications. Assistant replies remain visible: do not instruct a subscriber to issue a new task for every reply, or it can create a feedback loop. Actual ChatGPT callback acceptance requires an installed client and subscription; this export does not include a receipt proving that end-to-end path.

Topic listing covers known Hermes sessions, not all Telegram topics. Search examines at most the latest 5000 eligible messages per request. Telegram's Bot API supports private topic creation/rename but documents close/reopen only for forum supergroups; those operations are absent. Topic remote readback is not available through Bot API. Same-user processes/plugins are trusted, not sandboxed. Private gateway APIs are version-sensitive. No executable test suite or private integration fixtures are included.

References: [OpenAI dots](https://learn.chatgpt.com/docs/dots), [custom MCP connection](https://developers.openai.com/plugins/deploy/connect-chatgpt), [MCP Events](https://developers.openai.com/plugins/build/mcp-events), [Hermes](https://hermes-agent.nousresearch.com/docs/).
