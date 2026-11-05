import argparse
import asyncio
import base64
import contextlib
import json
import logging
import random
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import websockets


PATHS = frozenset({"/healthz", "/mcp", "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-authorization-server", "/register", "/authorize", "/token", "/revoke"})
HEADERS = frozenset({"content-type", "accept", "authorization", "origin", "mcp-protocol-version", "cookie"})


async def run(config):
    base = urlsplit(config["base_url"])
    if base.scheme != "https" or base.path or base.query or base.fragment or base.username or base.port not in (None, 443):
        raise ValueError("Invalid public origin")
    secret = json.loads(Path(config["relay_credentials"]).read_text())["bridge_token"]
    address = "wss://" + base.netloc + "/internal/bridge"
    semaphore = asyncio.Semaphore(24)
    delay = 1
    async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{config['port']}", timeout=62, follow_redirects=False, trust_env=False) as client:
        async def forward(socket, item):
            async with semaphore:
                identifier = item.get("id")
                try:
                    path = item["path"]
                    parsed = urlsplit(path)
                    if parsed.scheme or parsed.netloc or parsed.path not in PATHS or parsed.fragment or len(path) > 65536:
                        raise ValueError("Invalid path")
                    if item["method"] not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"}:
                        raise ValueError("Invalid method")
                    body = base64.b64decode(item["body"], validate=True)
                    if len(body) > 65536:
                        raise ValueError("Invalid body")
                    headers = [(k, v) for k, v in item["headers"] if k.lower() in HEADERS]
                    headers.append(("Host", base.netloc))
                    response = await client.request(item["method"], path, headers=headers, content=body)
                    if len(response.content) > 8 * 1024 * 1024:
                        result = {"id": identifier, "status": 502, "headers": [], "body": ""}
                    else:
                        result = {"id": identifier, "status": response.status_code, "headers": list(response.headers.multi_items()), "body": base64.b64encode(response.content).decode()}
                except Exception:
                    result = {"id": identifier, "status": 502, "headers": [], "body": ""}
                await socket.send(json.dumps(result, separators=(",", ":")))

        async def heartbeat(socket):
            while True:
                await asyncio.sleep(20)
                await socket.send('{"type":"heartbeat"}')

        while True:
            tasks = set()
            try:
                async with websockets.connect(address, additional_headers={"Authorization": "Bearer " + secret}, max_size=131072, ping_interval=20, ping_timeout=20, open_timeout=20, close_timeout=5) as socket:
                    logging.warning("Private HTTPS bridge connected")
                    delay = 1
                    beat = asyncio.create_task(heartbeat(socket))
                    tasks.add(beat)
                    async for raw in socket:
                        item = json.loads(raw)
                        if item.get("type") == "heartbeat":
                            continue
                        if len(tasks) > 32:
                            await socket.send(json.dumps({"id": item.get("id"), "status": 429, "headers": [], "body": ""}))
                            continue
                        task = asyncio.create_task(forward(socket, item))
                        tasks.add(task)
                        task.add_done_callback(tasks.discard)
            except asyncio.CancelledError:
                raise
            except Exception:
                logging.warning("Private HTTPS bridge reconnecting")
            finally:
                for task in tasks:
                    task.cancel()
                for task in tasks:
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        await task
            await asyncio.sleep(delay + random.random())
            delay = min(delay * 2, 30)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text())
    asyncio.run(run(config))


if __name__ == "__main__":
    main()
