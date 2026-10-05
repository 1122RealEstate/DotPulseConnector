"""This Hermes' side of DotPulse Link: its state on disk, and what it asks the Link service.

Three things live under ``<hermes home>/dotpulse/link/``, all mode 600 in a mode 700 directory:

* ``agent.json`` — this installation's long-lived X25519 key and the name it shows a phone;
* ``links.json`` — one entry per connected phone: the link credential, the phone's public key and
  what the link may carry. This credential is what outlives a pairing; the Pairing ID does not;
* ``claims/<id>.json`` — a pairing waiting for its owner's answer. It holds the claim credential,
  never the Pairing ID, and is deleted the moment the pairing closes either way.

The Pairing ID itself is never written anywhere and never logged.

Standard library only for everything that talks HTTP; the key agreement is in ``link_crypto``.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

import link_crypto

log = logging.getLogger("dotpulse")

#: Where DotPulse's own Link service lives. It is written here and nowhere else: it never arrives
#: in what the user pastes, so no message can send a Hermes to another service. DOTPULSE_LINK_URL
#: overrides it for development against a service of one's own.
OFFICIAL_URL = "https://link.dotpulse.app"
SCHEME = "DP1-HMAC-SHA256"
#: This connector, and the wire protocol it speaks with the Link service.
VERSION = "0.4.1"
PROTOCOL = 1
_ID = re.compile(r"[0-9a-f]{32}\Z")


class LinkError(Exception):
    """Something this Hermes could not do. ``code`` is stable; the message is for a person."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------- where things are

def home() -> str:
    return os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes")


def state_dir() -> str:
    path = os.path.join(home(), "dotpulse", "link")
    os.makedirs(os.path.join(path, "claims"), mode=0o700, exist_ok=True)
    return path


def service_url() -> str:
    """The Link service, or "" when this Hermes has none. https only, except on this machine."""
    url = (os.environ.get("DOTPULSE_LINK_URL") or OFFICIAL_URL).strip().rstrip("/")
    if not url:
        return ""
    parts = urllib.parse.urlsplit(url)
    local = parts.hostname in ("127.0.0.1", "localhost", "::1")
    if parts.scheme == "https" or (parts.scheme == "http" and local):
        return url if parts.hostname and not parts.query and not parts.fragment and not parts.username else ""
    return ""


def _write(path: str, value) -> None:
    """Whole or not at all, and never readable by anyone else."""
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(value, f)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read(path: str, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


class _Locked:
    """links.json is edited by more than one process (a pairing, the agent, a revocation)."""

    def __enter__(self):
        self._f = open(os.path.join(state_dir(), ".lock"), "a+")
        fcntl.flock(self._f, fcntl.LOCK_EX)
        return self

    def __exit__(self, *_):
        fcntl.flock(self._f, fcntl.LOCK_UN)
        self._f.close()


# ---------------------------------------------------------------------- identity and links

def agent() -> dict:
    """This installation's key and name, created the first time they are needed."""
    path = os.path.join(state_dir(), "agent.json")
    with _Locked():
        me = _read(path, {})
        if not re.fullmatch(r"[0-9a-f]{64}", str(me.get("key", ""))):
            me = {"key": link_crypto.new_private(), "created": int(time.time())}
            _write(path, me)
    name = (os.environ.get("DOTPULSE_AGENT_NAME") or "").strip() or "Hermes · " + socket.gethostname().split(".")[0]
    return {"key": me["key"], "pub": link_crypto.public_of(me["key"]), "name": name[:64]}


def links() -> list:
    return [l for l in _read(os.path.join(state_dir(), "links.json"), []) if isinstance(l, dict) and _ID.match(str(l.get("link_id", "")))]


def _save_links(rows: list) -> None:
    _write(os.path.join(state_dir(), "links.json"), rows)


def add_link(row: dict) -> None:
    with _Locked():
        _save_links([l for l in links() if l["link_id"] != row["link_id"]] + [row])


def update_link(link_id: str, **changes) -> None:
    with _Locked():
        _save_links([dict(l, **changes) if l["link_id"] == link_id else l for l in links()])


def forget_link(link_id: str) -> bool:
    """Erase everything this machine holds about one link: its credential, the phone's key and
    name, what it was granted, and the record of the pairing that made it. Nothing else is
    touched: not this Hermes' own key, not other links, and nothing of Hermes itself. After
    this, only a new pairing connects that phone again."""
    with _Locked():
        rows = links()
        kept = [l for l in rows if l["link_id"] != link_id]
        if len(kept) != len(rows):
            _save_links(kept)
        claims = os.path.join(state_dir(), "claims")
        for name in os.listdir(claims):
            path = os.path.join(claims, name)
            if (_read(path, None) or {}).get("link_id") == link_id:
                try:
                    os.unlink(path)
                except OSError:
                    pass
    return len(kept) != len(rows)


def find_links(prefix: str) -> list:
    prefix = (prefix or "").strip().lower()
    return [l for l in links() if re.fullmatch(r"[0-9a-f]{6,32}", prefix) and l["link_id"].startswith(prefix)]


# ---------------------------------------------------------------------- talking to the service

def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def authorization(kid: str, secret: str, method: str, target: str, body: bytes = b"", now: float | None = None) -> str:
    ts, nonce = int(time.time() if now is None else now), secrets.token_hex(8)
    text = "\n".join((method.upper(), target, str(ts), nonce, hashlib.sha256(body).hexdigest()))
    sig = _b64url(hmac.new(secret.encode(), text.encode(), hashlib.sha256).digest())
    return '%s kid="%s", ts=%d, nonce=%s, sig=%s' % (SCHEME, kid, ts, nonce, sig)


def call(method: str, path: str, body=None, kid: str = "", secret: str = "", timeout: float = 15.0) -> tuple:
    """``(status, json)``. Raises ``LinkError`` only when the service could not be reached at all."""
    base = service_url()
    if not base:
        raise LinkError("not-configured", "Este Hermes no tiene configurado el servicio DotPulse Link.")
    prefix = urllib.parse.urlsplit(base).path.rstrip("/")
    data = b"" if body is None else json.dumps(body, separators=(",", ":")).encode()
    request = urllib.request.Request(base + path, data=data or None, method=method)
    if data:
        request.add_header("Content-Type", "application/json")
    if kid:
        request.add_header("Authorization", authorization(kid, secret, method, prefix + path, data))
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read(65536) or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read(65536) or b"{}")
        except ValueError:
            return e.code, {}
    except (urllib.error.URLError, OSError, ValueError) as e:
        # Never the URL or anything sent: only what kind of failure it was.
        raise LinkError("unreachable", "No pude contactar con DotPulse (%s)." % type(getattr(e, "reason", e)).__name__)


def _code_of(payload: dict) -> str:
    error = payload.get("error") if isinstance(payload, dict) else None
    return error.get("code", "") if isinstance(error, dict) else ""


def service_check() -> dict:
    """Is the Link service there, and do the two of us speak the same protocol? Asked before a
    Pairing ID is presented, so that an outdated connector never spends one for nothing."""
    try:
        status, answer = call("GET", "/v1/health", timeout=8)
    except LinkError as e:
        return {"reachable": False, "compatible": False, "reason": e.code}
    speaks = answer.get("protocol") if status == 200 and isinstance(answer, dict) else None
    low, high = (speaks or {}).get("min"), (speaks or {}).get("max")
    compatible = isinstance(low, int) and isinstance(high, int) and low <= PROTOCOL <= high
    return {"reachable": status == 200, "compatible": compatible, "reason": "" if compatible else "incompatible"}


# ---------------------------------------------------------------------- pairing

def redeem(pairing_id: str, origin: str) -> dict:
    """Present a Pairing ID. Returns ``{"state": ...}``; on ``pending`` also the device's name and
    the verification code, and the claim is left on disk for the agent to finish.

    One attempt. Whatever comes back, the Pairing ID is spent and is not kept.
    """
    check = service_check()
    if not check["reachable"]:
        raise LinkError(check["reason"] if check["reason"] in ("not-configured", "unreachable") else "unreachable", "No pude contactar con DotPulse.")
    if not check["compatible"]:
        raise LinkError("incompatible", "Este conector no es compatible con el servicio.")
    me = agent()
    pairing_key = link_crypto.key(pairing_id)
    body = {"lookup": link_crypto.lookup(pairing_id),
            "agent": {"name": me["name"], "pub": me["pub"], "tag": link_crypto.tag(pairing_key, "agent", me["pub"]), "origin": origin}}
    status, answer = call("POST", "/v1/pairings/redeem", body)
    if status == 429:
        return {"state": "slow-down"}
    state = answer.get("state") if status == 200 else None
    if state in ("expired", "rejected"):
        return {"state": state}
    if state != "pending":
        return {"state": "rejected"}    # anything unexpected fails closed
    device = answer.get("device") or {}
    device_pub = str(device.get("pub", ""))
    claim_id, claim_secret = str(answer.get("claim_id", "")), str(answer.get("claim_secret", ""))
    if not (_ID.match(claim_id) and claim_secret and re.fullmatch(r"[0-9a-f]{64}", device_pub)
            and link_crypto.tag_ok(pairing_key, "device", device_pub, str(device.get("tag", "")))):
        # The phone behind this claim could not prove it holds the Pairing ID. Walk away.
        return {"state": "unverified"}
    name = "".join(ch for ch in str(device.get("name", "")) if ch.isprintable())[:64] or "iPhone"
    _write(os.path.join(state_dir(), "claims", claim_id + ".json"),
           {"claim_id": claim_id, "secret": claim_secret, "device_pub": device_pub, "device_name": name, "origin": origin,
            "confirm_by": int(answer.get("confirm_by") or time.time() + 120), "created": int(time.time()),
            # The owner of this Hermes has not yet said that phone is theirs. Until they do,
            # an approval on the phone is not enough: see ``confirm_claim``.
            "confirmed": False})
    return {"state": "pending", "claim_id": claim_id, "device": name,
            "code": link_crypto.code(pairing_key, device_pub, me["pub"]), "confirm_by": int(answer.get("confirm_by") or 0)}


def claim_file(claim_id: str) -> str:
    return os.path.join(state_dir(), "claims", claim_id + ".json")


def outcome_file(claim_id: str) -> str:
    return os.path.join(state_dir(), "claims", claim_id + ".done")


def outcome(claim_id: str) -> dict | None:
    """How a claim ended, once it has: ``{"state": connected|rejected|expired|revoked|failed, ...}``."""
    return _read(outcome_file(claim_id), None) if _ID.match(claim_id or "") else None


def waiting_claims() -> list:
    """Claims whose owner has not answered here yet."""
    return [c for c in pending_claims() if not c.get("confirmed")]


def confirm_claim(claim_id: str) -> dict | None:
    """The owner of this Hermes says: that phone is mine and it shows this code.

    Pasting a Pairing ID is what lets a phone in, and a Pairing ID can be someone else's. The
    approval on the phone is given by whoever holds that phone, so it proves nothing to this
    side. This is this side's own yes, and without it the credential is never collected.
    """
    with _Locked():
        claim = _read(claim_file(claim_id), None) if _ID.match(claim_id or "") else None
        if not isinstance(claim, dict):
            return None
        claim["confirmed"] = True
        _write(claim_file(claim_id), claim)
    return claim


def reject_claim(claim_id: str) -> bool:
    """The owner of this Hermes says no. The claim is withdrawn at the service, so an approval on
    the phone, already given or not, leads nowhere."""
    claim = _read(claim_file(claim_id), None) if _ID.match(claim_id or "") else None
    if not isinstance(claim, dict):
        return False
    try:
        call("DELETE", "/v1/claims/%s" % claim_id, kid="lc:" + claim_id, secret=claim["secret"])
    except LinkError:
        pass    # offline: dropping the claim below is enough, nothing can collect a credential without it
    _write(outcome_file(claim_id), {"state": "hermes-rejected", "device": claim.get("device_name", "")})
    try:
        os.unlink(claim_file(claim_id))
    except OSError:
        pass
    return True


def finish_claim(claim: dict, wait: float = 20.0) -> dict | None:
    """One step for a waiting claim: ask the service; if the phone approved **and** the owner
    confirmed here, collect the credential and keep it. Returns the outcome when the claim is
    closed, None while it is still open."""
    claim_id, kid = claim["claim_id"], "lc:" + claim["claim_id"]
    current = _read(claim_file(claim_id), None)
    if not isinstance(current, dict):
        return outcome(claim_id) or {"state": "failed", "device": claim.get("device_name", "")}    # withdrawn meanwhile
    status, answer = call("GET", "/v1/claims/%s?wait=%d" % (claim_id, int(wait)), kid=kid, secret=claim["secret"], timeout=wait + 10)
    state = answer.get("state") if status == 200 else None
    if state == "pending":
        return None
    if state == "authorized":
        current = _read(claim_file(claim_id), None)
        if not isinstance(current, dict):
            return outcome(claim_id) or {"state": "failed", "device": claim.get("device_name", "")}
        if not current.get("confirmed"):
            # Approved on the phone, not yet here. The service gives the pair two minutes.
            time.sleep(0.5)
            return None
    result = {"state": state if state in ("rejected", "expired", "revoked") else "failed", "device": claim["device_name"]}
    if state == "authorized":
        status, answer = call("POST", "/v1/claims/%s/start" % claim_id, kid=kid, secret=claim["secret"])
        link_id, secret = str(answer.get("link_id", "")), str(answer.get("secret", ""))
        device = answer.get("device") or {}
        # The phone's key must be the one this claim verified with the Pairing ID. If the service
        # says otherwise now, it is not the phone that was approved.
        if status == 200 and _ID.match(link_id) and secret and device.get("pub") == claim["device_pub"]:
            add_link({"link_id": link_id, "secret": secret, "device_pub": claim["device_pub"], "device_name": claim["device_name"],
                      "capabilities": [c for c in answer.get("capabilities", []) if isinstance(c, str)],
                      "origin": claim["origin"], "created": int(time.time()), "rotated": int(time.time())})
            result = {"state": "connected", "device": claim["device_name"], "link_id": link_id}
    _write(outcome_file(claim_id), result)
    try:
        os.unlink(claim_file(claim_id))
    except OSError:
        pass
    return result


def pending_claims() -> list:
    out = []
    folder = os.path.join(state_dir(), "claims")
    for name in sorted(os.listdir(folder)):
        path = os.path.join(folder, name)
        if name.endswith(".json"):
            claim = _read(path, None)
            if isinstance(claim, dict) and _ID.match(str(claim.get("claim_id", ""))) and claim.get("secret"):
                out.append(claim)
        elif name.endswith(".done"):
            try:
                if os.path.getmtime(path) < time.time() - 3600:
                    os.unlink(path)     # an outcome nobody came back for
            except OSError:
                pass
    return out


# ---------------------------------------------------------------------- links, once connected

def link_status(link: dict) -> dict:
    """What the service says about a link right now: state and the capabilities it grants."""
    kid = "la:" + link["link_id"]
    status, answer = call("GET", "/v1/links/%s" % link["link_id"], kid=kid, secret=link["secret"])
    if status == 403 and _code_of(answer) == "revoked":
        forget_link(link["link_id"])
        return {"link_id": link["link_id"], "device": link.get("device_name", ""), "state": "revoked", "capabilities": []}
    if status != 200:
        return {"link_id": link["link_id"], "device": link.get("device_name", ""), "state": "unknown", "capabilities": []}
    return {"link_id": link["link_id"], "device": link.get("device_name", ""), "state": answer.get("state"), "online": bool(answer.get("online")),
            "capabilities": answer.get("capabilities", [])}


def revoke(link: dict) -> bool:
    """Tell the service, then forget the credential here whatever it answered."""
    try:
        call("DELETE", "/v1/links/%s" % link["link_id"], kid="la:" + link["link_id"], secret=link["secret"])
    except LinkError:
        pass    # offline: the credential is still destroyed on this side
    return forget_link(link["link_id"])


def rotate(link: dict) -> bool:
    """Replace the link credential. The old one dies at the first request signed with the new one."""
    status, answer = call("POST", "/v1/links/%s/rotate" % link["link_id"], kid="la:" + link["link_id"], secret=link["secret"])
    fresh = str(answer.get("secret", "")) if status == 200 else ""
    if not fresh:
        return False
    update_link(link["link_id"], secret=fresh, rotated=int(time.time()))
    return True


# ---------------------------------------------------------------------- the agent process

def agent_running() -> bool:
    """True while a link agent holds its lock for this Hermes home."""
    try:
        with open(os.path.join(state_dir(), "agent.lock"), "a+") as f:
            try:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                return True
            fcntl.flock(f, fcntl.LOCK_UN)
    except OSError:
        pass
    return False


def ensure_agent() -> bool:
    """Start the link agent if there is anything for it to do and it is not already running.

    It is its own process on purpose: it must outlive whichever Hermes command happened to load
    this plugin. Fixed argument list, no shell, nothing from a chat in it.
    """
    if not service_url() or not (links() or pending_claims()):
        return False
    if agent_running():
        return True
    here = os.path.dirname(os.path.realpath(__file__))
    try:
        with open(os.path.join(state_dir(), "agent.log"), "ab") as out:
            subprocess.Popen([sys.executable, os.path.join(here, "link_agent.py")], env=dict(os.environ, HERMES_HOME=home()),
                             stdin=subprocess.DEVNULL, stdout=out, stderr=out, start_new_session=True, close_fds=True, cwd=here)
    except OSError:
        log.exception("dotpulse: the link agent could not be started")
        return False
    return True
