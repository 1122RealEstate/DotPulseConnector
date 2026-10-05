"""Tell the DotPulse Push Relay that something finished or needs the owner, even with no phone connected.

Off unless a relay is configured (``<hermes home>/dotpulse/relay.json``, written by
``python3 dotpulse_push.py enroll <url>``): then nothing is registered and every function here
returns at once. Standard library only, and it imports nothing from the relay: the two talk HTTP.

A hook only writes a row to a small outbox; a background thread posts it. Nothing here does
network I/O on the agent's path, and nothing here ever raises into Hermes.

What leaves this server is deliberately little: which Dot, which conversation, what kind of
thing happened. Never the Hermes token, a command, a path, tool arguments or a message.
"""
from __future__ import annotations

import atexit
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

log = logging.getLogger("dotpulse")

SCHEME = "DP1-HMAC-SHA256"
TICKET_CONTEXT = b"dotpulse-device-ticket-v1\n"
OUTBOX_MAX = 500
#: Seconds an event is worth delivering, by kind. The relay applies the same ceiling to Apple.
LIFETIME = {"reply": 3600, "question": 900, "task": 6 * 3600, "autonomous": 3600, "error": 6 * 3600, "activity": 900}
#: Chats where the owner is already reading the answer: no second notification for those.
DEFAULT_SKIP = "cli,telegram,discord,slack,whatsapp,signal,matrix"

_lock = threading.RLock()
_wake = threading.Event()
_flusher = None
_busy: dict = {}     # session id -> True while a turn of this process is running


def _home() -> str:
    return os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes")


def _state_dir() -> str:
    return os.path.join(_home(), "dotpulse")


def _config_file() -> str:
    return os.path.join(_state_dir(), "relay.json")


def _valid_url(url: str) -> bool:
    """HTTPS anywhere; plain HTTP only to this machine."""
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    if parts.scheme == "https":
        return bool(parts.hostname)
    return parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost", "::1") and port is not None


def config():
    """``{"url", "phone_url", "installation", "secret"}``, or None when push is not set up."""
    try:
        with open(_config_file()) as f:
            o = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(o, dict):
        return None
    url = (os.environ.get("DOTPULSE_RELAY_URL") or str(o.get("url", ""))).strip().rstrip("/")
    phone = (os.environ.get("DOTPULSE_RELAY_PHONE_URL") or str(o.get("phone_url", "")) or url).strip().rstrip("/")
    installation, secret = str(o.get("installation", "")), str(o.get("secret", ""))
    if not (_valid_url(url) and _valid_url(phone) and re.fullmatch(r"[0-9a-f]{32}", installation) and re.fullmatch(r"[A-Za-z0-9_-]{32,128}", secret)):
        return None
    return {"url": url, "phone_url": phone, "installation": installation, "secret": secret}


# ----- signing (the same scheme the relay verifies; see docs/PUSH.md)

def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _authorization(kid: str, secret: str, method: str, target: str, body: bytes, now: float | None = None) -> str:
    ts, nonce = int(time.time() if now is None else now), secrets.token_hex(8)
    text = "\n".join((method, target, str(ts), nonce, hashlib.sha256(body).hexdigest()))
    sig = _b64url(hmac.new(secret.encode(), text.encode(), hashlib.sha256).digest())
    return '%s kid="%s", ts=%d, nonce=%s, sig=%s' % (SCHEME, kid, ts, nonce, sig)


def _call(cfg: dict, method: str, path: str, body=None, timeout: float = 5.0):
    """``(status, json or None)``; status 0 when the relay could not be reached."""
    raw = b"" if body is None else json.dumps(body, separators=(",", ":")).encode()
    target = urllib.parse.urlsplit(cfg["url"]).path.rstrip("/") + path
    request = urllib.request.Request(cfg["url"] + path, data=raw if raw else None, method=method, headers={
        "Authorization": _authorization("i:" + cfg["installation"], cfg["secret"], method, target, raw),
        "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as r:
            status, text = r.status, r.read(65536)
    except urllib.error.HTTPError as e:
        status, text = e.code, e.read(65536)
    except Exception:
        return 0, None
    try:
        return status, json.loads(text) if text else None
    except ValueError:
        return status, None


# ----- what pairing needs from push

def ticket(secret: str, device_id: str) -> str:
    return _b64url(hmac.new(secret.encode(), TICKET_CONTEXT + device_id.encode(), hashlib.sha256).digest())


def hello_for(device_id: str):
    """What `dotpulse-hello` adds for a paired phone: where the relay is and its ticket to
    register there. None when push is off."""
    cfg = config()
    if not cfg or not re.fullmatch(r"[0-9a-f]{32}", device_id or ""):
        return None
    return {"url": cfg["phone_url"], "installation": cfg["installation"], "device": device_id, "ticket": ticket(cfg["secret"], device_id)}


def tunnel_ports() -> list:
    """Loopback ports a paired phone must also be allowed to forward: the relay's, when the
    phone reaches it through the SSH tunnel rather than over the internet."""
    cfg = config()
    if not cfg:
        return []
    parts = urllib.parse.urlsplit(cfg["phone_url"])
    return [parts.port] if parts.scheme == "http" and parts.port else []


def _in_background(method: str, path: str) -> None:
    cfg = config()
    if not cfg:
        return

    def run():
        # A relay that is restarting must still hear that a phone was revoked: a few tries.
        for pause in (2.0, 10.0, 30.0, None):
            status, _ = _call(cfg, method, path)
            if status in (200, 204):
                return
            if pause is None or (400 <= status < 500 and status != 429):
                break
            time.sleep(pause)
        log.warning("dotpulse: relay did not take %s (status %s)", method, status or "unreachable")

    threading.Thread(target=run, name="dotpulse-relay", daemon=True).start()


def device_allowed(device_id: str) -> None:
    """A phone was (re)authorised: lift any earlier revocation at the relay. Best effort."""
    _in_background("PUT", "/v1/installations/%s/devices/%s" % ((config() or {}).get("installation", ""), device_id))


def device_revoked(device_id: str) -> None:
    """A phone lost its access here: it must stop receiving this server's notifications too."""
    _in_background("DELETE", "/v1/installations/%s/devices/%s" % ((config() or {}).get("installation", ""), device_id))


# ----- outbox

def _db() -> sqlite3.Connection:
    os.makedirs(_state_dir(), mode=0o700, exist_ok=True)
    path = os.path.join(_state_dir(), "outbox.db")
    db = sqlite3.connect(path, timeout=2.0, isolation_level=None)
    db.execute("CREATE TABLE IF NOT EXISTS outbox(id TEXT PRIMARY KEY, body TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL, "
               "attempts INTEGER NOT NULL DEFAULT 0, next_attempt REAL NOT NULL DEFAULT 0)")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return db


def _clean(text, pattern: str = r"[^A-Za-z0-9._:@-]", limit: int = 128) -> str:
    return re.sub(pattern, "-", str(text or ""))[:limit]


def emit(kind: str, event_id: str, dot: str = "", conversation: str = "", collapse: str = "", withdraw: bool = False,
         activity=None, now: float | None = None) -> bool:
    """Queue one event for the relay. True when it was queued (or already was)."""
    if kind not in LIFETIME or not config():
        return False
    now = time.time() if now is None else now
    event = {"id": _clean(event_id, limit=200), "kind": kind, "created": int(now), "expires": int(now + LIFETIME[kind])}
    if dot:
        event["dot"] = _clean(dot, r"[^A-Za-z0-9._-]", 64)
    if conversation:
        event["conversation"] = _clean(conversation)
    if collapse:
        event["collapse"] = _clean(collapse, limit=200)
    if withdraw:
        event["withdraw"] = True
    if activity:
        event["activity"] = activity
    try:
        with _lock:
            db = _db()
            try:
                db.execute("INSERT OR IGNORE INTO outbox(id, body, created, expires) VALUES(?,?,?,?)",
                           (event["id"], json.dumps(event, separators=(",", ":")), now, event["expires"]))
                # Never grows without bound if the relay is away for long: the oldest go first.
                db.execute("DELETE FROM outbox WHERE id NOT IN (SELECT id FROM outbox ORDER BY created DESC LIMIT ?)", (OUTBOX_MAX,))
            finally:
                db.close()
    except (sqlite3.Error, OSError):
        log.warning("dotpulse: could not queue a push event")
        return False
    _start_flusher()
    _wake.set()
    return True


def flush(now: float | None = None, timeout: float = 5.0, budget: float | None = None):
    """Post what is due. Returns seconds until the next row is due, or None when the outbox is empty.
    ``budget`` bounds the whole pass, for a process that is about to exit."""
    cfg = config()
    if not cfg:
        return None
    started = time.time()
    now = started if now is None else now
    with _lock:
        db = _db()
        try:
            db.execute("DELETE FROM outbox WHERE expires<=?", (now,))
            rows = db.execute("SELECT id, body, attempts FROM outbox WHERE next_attempt<=? ORDER BY created LIMIT 50", (now,)).fetchall()
        finally:
            db.close()
    for event_id, body, attempts in rows:
        if budget is not None and time.time() - started > budget:
            break
        status, _ = _call(cfg, "POST", "/v1/installations/%s/events" % cfg["installation"], json.loads(body), timeout=timeout)
        with _lock:
            db = _db()
            try:
                if 200 <= status < 300 or (400 <= status < 500 and status != 429):
                    # Taken, or refused for good: either way it is not sent again.
                    if status >= 400:
                        log.warning("dotpulse: relay refused an event (status %d); dropped", status)
                    db.execute("DELETE FROM outbox WHERE id=?", (event_id,))
                else:
                    # Unreachable, busy or failing: 2, 4, 8 … 300 s, with jitter, until the event expires.
                    delay = min(300.0, 2.0 * 2 ** attempts) * (0.5 + secrets.randbelow(1000) / 2000.0)
                    db.execute("UPDATE outbox SET attempts=attempts+1, next_attempt=? WHERE id=?", (now + delay, event_id))
            finally:
                db.close()
    with _lock:
        db = _db()
        try:
            row = db.execute("SELECT MIN(next_attempt) FROM outbox").fetchone()
        finally:
            db.close()
    return None if row is None or row[0] is None else max(0.0, row[0] - time.time())


def _run() -> None:
    while True:
        try:
            pause = flush()
        except Exception:
            log.exception("dotpulse: push outbox failed; will retry")
            pause = 30.0
        _wake.wait(60.0 if pause is None else min(60.0, max(0.2, pause)))
        _wake.clear()


def _start_flusher() -> None:
    global _flusher
    with _lock:
        if _flusher is None or not _flusher.is_alive():
            _flusher = threading.Thread(target=_run, name="dotpulse-push", daemon=True)
            _flusher.start()


def _last_chance() -> None:
    # A short-lived process (a cron run) may end right after queueing: one quick try, and
    # whatever is left stays in the outbox for the next process.
    try:
        flush(timeout=2.0, budget=3.0)
    except Exception:
        pass


# ----- Hermes hooks → events

def dot_id() -> str:
    """The Dot this Hermes home is: the profile's name, or ``default``."""
    home = os.path.normpath(_home())
    return os.path.basename(home) if os.path.basename(os.path.dirname(home)) == "profiles" else "default"


def _skipped(platform) -> bool:
    return str(platform or "").lower() in {p.strip() for p in os.environ.get("DOTPULSE_PUSH_SKIP_PLATFORMS", DEFAULT_SKIP).lower().split(",") if p.strip()}


def _is_cron(session_id) -> bool:
    return str(session_id or "").startswith("cron_")


def _turn_started(session_id="", turn_id="", platform="", **_):
    try:
        if not session_id or _skipped(platform) or _busy.get(session_id) == turn_id:
            return None
        _busy[session_id] = turn_id
        if len(_busy) > 200:
            _busy.pop(next(iter(_busy)))
        emit("activity", "busy.%s.%s" % (session_id, turn_id or int(time.time())), dot_id(), session_id,
             activity={"state": "cronRunning" if _is_cron(session_id) else "thinking"})
    except Exception:
        log.debug("dotpulse: push hook failed", exc_info=True)
    return None    # this hook may inject context; this plugin never does


def _turn_ended(session_id="", turn_id="", completed=False, failed=False, interrupted=False, platform="", **_):
    try:
        if not session_id or _skipped(platform):
            return
        _busy.pop(session_id, None)
        event_id = "turn.%s.%s" % (session_id, turn_id or int(time.time()))
        if failed:
            kind, activity = "error", {"state": "error", "outcome": "failed"}
        elif interrupted or not completed:
            # Stopped by the owner: nothing to announce, only a card to close.
            kind, activity = "activity", {"state": "idle", "outcome": "cancelled"}
        else:
            kind, activity = ("task" if _is_cron(session_id) else "reply"), {"state": "success", "outcome": "finished"}
        emit(kind, event_id, dot_id(), session_id, activity=activity)
    except Exception:
        log.debug("dotpulse: push hook failed", exc_info=True)


def _approval_key(kwargs: dict):
    session = kwargs.get("session_id") or kwargs.get("session_key") or ""
    call = kwargs.get("tool_call_id") or kwargs.get("request_id") or ""
    return session, "ask.%s.%s" % (session, call) if call else "ask.%s" % session


def _approval_asked(**kwargs):
    try:
        # A request a model answers by itself, or one folded into another, never reaches the owner.
        if kwargs.get("coalesced") or str(kwargs.get("surface", "")).startswith("smart"):
            return
        session, collapse = _approval_key(kwargs)
        if not session:
            return
        suffix = "" if kwargs.get("tool_call_id") or kwargs.get("request_id") else ".%d" % int(time.time())
        # The command itself stays here: the phone reads it from Hermes when the owner opens the chat.
        emit("question", collapse + suffix, dot_id(), session, collapse=collapse, activity={"state": "waitingForUser"})
    except Exception:
        log.debug("dotpulse: push hook failed", exc_info=True)


def _approval_answered(**kwargs):
    try:
        if kwargs.get("coalesced") or str(kwargs.get("surface", "")).startswith("smart") or str(kwargs.get("choice", "")).startswith("smart_"):
            return
        session, collapse = _approval_key(kwargs)
        if not session:
            return
        emit("question", "answered.%s.%d" % (collapse, int(time.time())), dot_id(), session, collapse=collapse, withdraw=True,
             activity={"state": "thinking"})
    except Exception:
        log.debug("dotpulse: push hook failed", exc_info=True)


def _kanban(state: str):
    def hook(task_id="", run_id="", profile_name="", **_):
        try:
            if task_id:
                emit("task", "kanban.%s.%s.%s" % (task_id, run_id, state), _clean(profile_name, r"[^A-Za-z0-9._-]", 64) or dot_id())
        except Exception:
            log.debug("dotpulse: push hook failed", exc_info=True)
    return hook


HOOKS = {
    "pre_llm_call": _turn_started,
    "on_session_end": _turn_ended,
    "pre_approval_request": _approval_asked,
    "post_approval_response": _approval_answered,
    "kanban_task_completed": _kanban("done"),
    "kanban_task_blocked": _kanban("blocked"),
}


def register(ctx) -> bool:
    """Observer hooks, only when a relay is configured. They return nothing and change nothing."""
    if not config():
        return False
    for name, callback in HOOKS.items():
        ctx.register_hook(name, callback)
    atexit.register(_last_chance)
    _start_flusher()    # whatever an earlier process left in the outbox
    log.info("dotpulse: push events go to the configured relay")
    return True


# ----- setting it up, by hand, on the server

def enroll(url: str, enroll_token: str, name: str = "", phone_url: str = "") -> dict:
    url = url.strip().rstrip("/")
    if not _valid_url(url) or (phone_url and not _valid_url(phone_url.strip())):
        raise ValueError("La URL del relay tiene que ser https://…, o http://127.0.0.1:<puerto> si corre en este mismo servidor.")
    request = urllib.request.Request(url + "/v1/installations", data=json.dumps({"name": name}).encode(), method="POST",
                                     headers={"Authorization": "Bearer " + enroll_token, "Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as r:
        answer = json.loads(r.read(65536))
    saved = {"url": url, "installation": answer["installation_id"], "secret": answer["secret"]}
    if phone_url:
        saved["phone_url"] = phone_url.strip().rstrip("/")
    os.makedirs(_state_dir(), mode=0o700, exist_ok=True)
    fd = os.open(_config_file() + ".new", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(saved, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(_config_file() + ".new", _config_file())
    return saved


def _main(argv: list) -> int:
    if len(argv) >= 3 and argv[1] == "enroll":
        import getpass
        token = os.environ.get("DOTPULSE_RELAY_ENROLL_TOKEN") or getpass.getpass("Token de alta del relay: ")
        try:
            saved = enroll(argv[2], token.strip(), name=os.uname().nodename, phone_url=argv[3] if len(argv) > 3 else "")
        except urllib.error.HTTPError as e:
            print("El relay rechazó el alta (HTTP %d). Revisa el token." % e.code, file=sys.stderr)
            return 1
        except Exception as e:
            print("No pude dar de alta esta instalación: %s" % e, file=sys.stderr)
            return 1
        print("Instalación %s dada de alta. Reinicia Hermes (gateway y `hermes serve`) para que empiece a avisar." % saved["installation"][:8])
        if tunnel_ports():
            print("El relay es local: los teléfonos llegarán a él por el túnel SSH. Los ya autorizados tienen que emparejarse otra vez.")
        return 0
    if len(argv) == 2 and argv[1] == "status":
        cfg = config()
        if not cfg:
            print("Push desactivado: no hay un relay configurado en %s" % _config_file())
            return 0
        status, body = _call(cfg, "GET", "/v1/installations/%s/policy" % cfg["installation"])
        print("Relay: %s · instalación %s · %s" % (cfg["url"], cfg["installation"][:8],
              "responde, %d dispositivo(s) registrado(s)" % body.get("devices", 0) if status == 200 and body else "no responde (estado %s)" % (status or "sin conexión")))
        return 0
    print("uso: python3 dotpulse_push.py enroll <url del relay> [url para el teléfono] | status", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
