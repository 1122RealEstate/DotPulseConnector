#!/usr/bin/env python3
"""The DotPulse link agent: the process that keeps this Hermes reachable from its paired phones.

It only ever dials out. One WebSocket per link goes to the Link service and stays up: heartbeat
every 20 s, reconnection with backoff when the network or the service goes away, and the same
credentials after a reboot, because they are on disk. Nothing listens on this machine and no port
is opened.

What a phone can reach through it is what its link was granted, checked here again for every
stream: today ``hermes.api``, the loopback port of ``hermes serve``. Bytes arrive sealed by the
phone and are opened here; the service in the middle forwards what it cannot read.

It also finishes pairings: a claim left by ``link_client.redeem`` is watched until its owner
answers on the phone, and only an approval turns it into a link.

A link the service reports as revoked is forgotten on the spot and never retried.

Started by the plugin (``link_client.ensure_agent``); one per Hermes home, held by a lock.
"""
from __future__ import annotations

import asyncio
import fcntl
import json
import logging
import os
import random
import struct
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

import link_client  # noqa: E402
import link_crypto  # noqa: E402

log = logging.getLogger("dotpulse.agent")

OPEN, DATA, CLOSE, RESET, HELLO, SEALED, NOTICE = 0x01, 0x02, 0x03, 0x04, 0x10, 0x11, 0x20
CHUNK = 16 * 1024
HEARTBEAT = 20.0
#: Without anything from the service for this long, the socket is dead whatever TCP says.
SILENCE = 75.0
BACKOFF_MAX = 60.0
ROTATE_AFTER = 30 * 86400
IDLE_EXIT = 120.0
CLOSE_REVOKED = 4403


def frame(kind: int, stream: int, payload: bytes = b"") -> bytes:
    return struct.pack(">BI", kind, stream) + payload


def _hermes() -> dict:
    """Where this machine's Hermes backend listens and its session token, or why not."""
    import hermes_backend
    port = hermes_backend.ensure_backend()
    token = hermes_backend.token_for(port) if port else None
    if not port or not token:
        return {"error": "backend"}
    return {"port": port, "token": token}


class Peer:
    """One attached link: the sealed session with its phone and the streams open through it."""

    def __init__(self, ws, link: dict, me: dict, hermes=_hermes):
        self.ws, self.link, self.me, self.hermes = ws, link, me, hermes
        self.session: link_crypto.Session | None = None
        self.streams: dict = {}
        self.port = None
        self.lock = asyncio.Lock()

    async def send(self, kind: int, stream: int, payload: bytes = b"", sealed: bool = False, session=None) -> None:
        async with self.lock:
            if sealed:
                if self.session is None or (session is not None and session is not self.session):
                    return    # that conversation is over; its bytes go nowhere
                payload = self.session.seal(kind, stream, payload)
            await self.ws.send_bytes(frame(kind, stream, payload))

    def drop_streams(self) -> None:
        for _, writer, task in self.streams.values():
            task.cancel()
            writer.close()
        self.streams.clear()

    async def on_hello(self, payload: bytes) -> None:
        """The phone (re)starts the conversation: everything before it is gone."""
        self.drop_streams()
        session = link_crypto.Session("agent", self.me["key"], self.link["device_pub"])
        session.accept(payload)
        self.session = session
        await self.send(HELLO, 0, session.hello())
        found = await asyncio.to_thread(self.hermes)
        self.port = found.get("port")
        said = {"v": 1, "capabilities": self.link.get("capabilities", [])}
        if self.port:
            said["hermes"] = {"token": found["token"]}
        else:
            said["error"] = found.get("error", "backend")
        # Only the phone holding the paired key can open this, so the token is never in the clear.
        await self.send(SEALED, 0, json.dumps(said, separators=(",", ":")).encode(), sealed=True)

    async def on_open(self, stream: int, capability: str) -> None:
        if self.session is None or stream in self.streams or capability not in self.link.get("capabilities", []) or capability != "hermes.api":
            return await self.send(RESET, stream, b"capability")
        if not self.port:
            return await self.send(RESET, stream, b"backend")
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", self.port), 5)
        except (OSError, asyncio.TimeoutError):
            return await self.send(RESET, stream, b"backend")
        self.streams[stream] = (reader, writer, asyncio.ensure_future(self.pump(stream, reader, self.session)))

    async def pump(self, stream: int, reader, session) -> None:
        """Hermes → phone, sealed, until Hermes is done with this connection."""
        try:
            while True:
                data = await reader.read(CHUNK)
                if not data:
                    break
                await self.send(DATA, stream, data, sealed=True, session=session)
            await self.send(CLOSE, stream)
        except (OSError, ConnectionError, RuntimeError):
            pass
        finally:
            entry = self.streams.pop(stream, None)
            if entry:
                entry[1].close()

    async def on_frame(self, data: bytes) -> None:
        if len(data) < 5:
            raise link_crypto.Sealed("frame")
        kind, stream = struct.unpack(">BI", data[:5])
        payload = data[5:]
        if kind == NOTICE:
            try:
                said = json.loads(payload)
            except ValueError:
                said = {}
            if said.get("peer") == "offline":
                self.drop_streams()
                self.session = None
        elif kind == HELLO:
            await self.on_hello(payload)
        elif kind == OPEN:
            await self.on_open(stream, payload.decode("ascii", "replace"))
        elif kind in (DATA, SEALED):
            if self.session is None:
                return
            # Opened in arrival order whatever stream it is for: the counter is the session's.
            plain = self.session.open(kind, stream, payload)
            entry = self.streams.get(stream) if kind == DATA else None
            if entry:
                try:
                    entry[1].write(plain)
                    await entry[1].drain()
                except (OSError, ConnectionError):
                    await self.close_stream(stream, RESET)
        elif kind == CLOSE:
            entry = self.streams.get(stream)
            if entry:
                try:
                    if entry[1].can_write_eof():
                        entry[1].write_eof()
                except (OSError, ConnectionError, RuntimeError):
                    pass
        elif kind == RESET:
            await self.close_stream(stream, None)

    async def close_stream(self, stream: int, tell) -> None:
        entry = self.streams.pop(stream, None)
        if entry:
            entry[2].cancel()
            entry[1].close()
        if tell is not None:
            await self.send(tell, stream)


def _socket_url(base: str, link_id: str) -> tuple:
    """``(url, signed target)`` of this link's socket."""
    parts = urllib.parse.urlsplit(base)
    path = parts.path.rstrip("/") + "/v1/links/%s/agent" % link_id
    return urllib.parse.urlunsplit(("wss" if parts.scheme == "https" else "ws", parts.netloc, path, "", "")), path


async def run_link(link_id: str, hermes=_hermes, stop: asyncio.Event | None = None) -> None:
    """Keep one link attached for as long as it exists on this machine."""
    import aiohttp
    attempt = 0
    me = await asyncio.to_thread(link_client.agent)
    short = link_id[:8]
    async with aiohttp.ClientSession() as http:
        while not (stop and stop.is_set()):
            link = next((l for l in link_client.links() if l["link_id"] == link_id), None)
            if link is None:
                return
            base = link_client.service_url()
            if not base:
                return
            revoked = False
            try:
                if time.time() - link.get("rotated", link.get("created", 0)) > ROTATE_AFTER:
                    if await asyncio.to_thread(link_client.rotate, link):
                        log.info("agent: link %s… credential rotated", short)
                        continue
                url, target = _socket_url(base, link_id)
                headers = {"Authorization": link_client.authorization("la:" + link_id, link["secret"], "GET", target)}
                async with http.ws_connect(url, headers=headers, heartbeat=HEARTBEAT, max_msg_size=(1 << 20) + 64, compress=0,
                                           timeout=aiohttp.ClientWSTimeout(ws_close=5)) as ws:
                    log.info("agent: link %s… attached", short)
                    attempt = 0
                    peer = Peer(ws, link, me, hermes)
                    try:
                        while True:
                            message = await ws.receive(timeout=SILENCE)
                            if message.type != aiohttp.WSMsgType.BINARY:
                                revoked = ws.close_code == CLOSE_REVOKED
                                break
                            await peer.on_frame(message.data)
                    except link_crypto.Sealed:
                        log.warning("agent: link %s… a frame did not open; dropping the session", short)
                    except asyncio.TimeoutError:
                        log.info("agent: link %s… went silent", short)
                    finally:
                        peer.drop_streams()
            except aiohttp.WSServerHandshakeError as e:
                if e.status == 403:
                    said = await asyncio.to_thread(_status_or_none, link)
                    revoked = bool(said) and said.get("state") == "revoked"
                else:
                    log.info("agent: link %s… refused (%d)", short, e.status)
            except (aiohttp.ClientError, OSError, asyncio.TimeoutError) as e:
                log.info("agent: link %s… unreachable (%s)", short, type(e).__name__)
            if revoked:
                # Revoked means revoked: the credential is destroyed here and nothing retries.
                link_client.forget_link(link_id)
                log.info("agent: link %s… was revoked; forgotten", short)
                return
            attempt += 1
            delay = min(BACKOFF_MAX, 2 ** min(attempt, 6)) * random.uniform(0.5, 1.0)
            if stop is None:
                await asyncio.sleep(delay)
            else:
                try:
                    await asyncio.wait_for(stop.wait(), delay)
                except asyncio.TimeoutError:
                    pass


def _status_or_none(link: dict):
    try:
        return link_client.link_status(link)
    except link_client.LinkError:
        return None


async def watch_claim(claim: dict) -> None:
    """Wait for the owner's answer to one pairing, then keep the link or drop the claim."""
    while True:
        try:
            done = await asyncio.to_thread(link_client.finish_claim, claim)
        except link_client.LinkError:
            done = None
            await asyncio.sleep(3)
        if done is not None:
            log.info("agent: a pairing ended: %s", done["state"])
            return
        if time.time() > claim.get("confirm_by", 0) + 300:
            # The service stopped answering long past the deadline: give the claim up locally.
            link_client._write(link_client.outcome_file(claim["claim_id"]), {"state": "failed", "device": claim["device_name"]})
            try:
                os.unlink(link_client.claim_file(claim["claim_id"]))
            except OSError:
                pass
            return


async def main(hermes=_hermes) -> int:
    lock = open(os.path.join(link_client.state_dir(), "agent.lock"), "a+")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return 0    # another agent already serves this Hermes home
    log.info("agent: started")
    running: dict = {}
    claims: dict = {}
    idle_since = None
    while True:
        wanted = {l["link_id"] for l in link_client.links()}
        for link_id in wanted - running.keys():
            running[link_id] = asyncio.ensure_future(run_link(link_id, hermes))
        for link_id in [l for l, task in running.items() if task.done()]:
            del running[link_id]
        for claim in link_client.pending_claims():
            if claim["claim_id"] not in claims:
                claims[claim["claim_id"]] = asyncio.ensure_future(watch_claim(claim))
        for claim_id in [c for c, task in claims.items() if task.done()]:
            del claims[claim_id]
        if running or claims:
            idle_since = None
        else:
            idle_since = idle_since or time.time()
            if time.time() - idle_since > IDLE_EXIT:
                log.info("agent: nothing to keep; exiting")
                return 0
        await asyncio.sleep(1.0)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        sys.exit(0)
