"""What is specific to Hermes: where its headless backend listens and how a phone reaches it.

Read-only. It looks at loopback listeners that are `hermes … serve`, confirms each with
``GET /api/health`` (the real health endpoint; ``/health`` is the web UI's path), and reads the
fixed session token from the process's own environment. Another agent backend would provide the
same three functions and reuse everything else.
"""
from __future__ import annotations

import base64
import getpass
import secrets
import shutil
import subprocess
import sys
import time
import glob
import hashlib
import json
import logging
import os
import re
import socket
import tempfile
import urllib.request


def _health(port: int) -> dict | None:
    try:
        with urllib.request.urlopen("http://127.0.0.1:%d/api/health" % port, timeout=3) as r:
            body = json.loads(r.read(2048).decode("utf-8", "replace"))
    except Exception:
        return None
    return body if isinstance(body, dict) and (body.get("ok") is True or "version" in body) else None


def _listeners() -> list[tuple[int, int]]:
    """(port, pid) of this user's processes listening on loopback. Linux `/proc`, no subprocess."""
    out = []
    for fd_dir in glob.glob("/proc/[0-9]*/"):
        pid = int(fd_dir.split("/")[2])
        try:
            with open(fd_dir + "cmdline", "rb") as f:
                cmd = f.read().replace(b"\0", b" ").decode("utf-8", "replace")
        except OSError:
            continue
        if "hermes" not in cmd or " serve" not in cmd:
            continue
        m = re.search(r"--port[ =](\d{2,5})", cmd)
        if m:
            out.append((int(m.group(1)), pid))
    return out


def _home() -> str:
    return os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes")


def _own_file() -> str:
    """Port and token of the backend this plugin started itself, if it ever had to."""
    return os.path.join(_home(), "dotpulse", "serve.json")


def _own() -> dict:
    try:
        with open(_own_file()) as f:
            o = json.load(f)
        if isinstance(o.get("port"), int) and re.fullmatch(r"[A-Za-z0-9_-]{8,512}", str(o.get("token", ""))):
            return o
    except (OSError, ValueError):
        pass
    return {}


def token_for(port: int) -> str | None:
    for p, pid in _listeners():
        if p != port:
            continue
        try:
            with open("/proc/%d/environ" % pid, "rb") as f:
                env = dict(e.split(b"=", 1) for e in f.read().split(b"\0") if b"=" in e)
        except OSError:
            break
        token = env.get(b"HERMES_DASHBOARD_SESSION_TOKEN", b"").decode("ascii", "replace")
        if re.fullmatch(r"[A-Za-z0-9_-]{8,512}", token):
            return token
        break
    # Where /proc cannot be read (or is not there), the backend we started ourselves is still ours.
    own = _own()
    if own.get("port") == port and _health(port):
        return own["token"]
    return None


def _hermes_binary() -> str | None:
    for candidate in (shutil.which("hermes"), os.path.expanduser("~/.local/bin/hermes"), "/usr/local/bin/hermes",
                      os.path.join(os.path.dirname(sys.executable), "hermes")):
        if candidate and os.access(candidate, os.X_OK):
            return candidate
    return None


def _port_free(port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # Without this, a backend that just died with a phone's connections still in TIME_WAIT
        # makes its own port look taken for a minute.
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _write_own(port: int, token: str) -> None:
    """serve.json, whole or not at all: a reader never sees it half written."""
    state_dir = os.path.dirname(_own_file())
    fd, tmp = tempfile.mkstemp(prefix=".serve-", dir=state_dir)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump({"port": port, "token": token}, f)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, _own_file())
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def start_backend(preferred: int = 9137, wait: float = 90.0) -> int | None:
    """Start `hermes serve` on loopback and leave it running. Only ever called when there is none.

    Fixed argument list, no shell. The bind is always 127.0.0.1: this never publishes Hermes.

    The first start picks a free port and records it. Every later start is a restart of that same
    backend and stays on that port: paired phones are pinned to it in ``authorized_keys``
    (``permitopen`` and the hello argument), so moving would lock them out for good. If the port
    is taken by something else, nothing is started and nothing is rewritten.
    """
    binary = _hermes_binary()
    if binary is None:
        return None
    own = _own()
    state_dir = os.path.dirname(_own_file())
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    if own:
        port, token = own["port"], own["token"]
        if not _port_free(port):
            logging.getLogger("dotpulse").warning("dotpulse: 127.0.0.1:%d is taken by something that is not this backend; not starting another", port)
            return None
    else:
        port = preferred
        while not _port_free(port):
            if port >= 65535:
                return None
            port += 1
        token = secrets.token_hex(32)
        _write_own(port, token)
    env = dict(os.environ, HERMES_DASHBOARD_SESSION_TOKEN=token)
    env.pop("HERMES_DESKTOP", None)   # that flag would make the backend fire cron and reap gateways itself
    with open(os.path.join(state_dir, "serve.log"), "ab") as log:
        subprocess.Popen([binary, "serve", "--host", "127.0.0.1", "--port", str(port)], env=env, stdin=subprocess.DEVNULL,
                         stdout=log, stderr=log, start_new_session=True, close_fds=True)
    deadline = time.time() + wait
    while time.time() < deadline:
        if _health(port):
            return port
        time.sleep(0.5)
    return None


def ensure_backend(preferred: int = 9137) -> int | None:
    """A running backend to pair with: the one already there, or a new one if there is none."""
    return find_backend(preferred) or start_backend(preferred)


def find_backend(preferred: int = 9137) -> int | None:
    """The loopback port of a running `hermes serve` that answers and has a fixed token."""
    own = _own().get("port")
    ports = sorted({p for p, _ in _listeners()} | ({own} if own else set()), key=lambda p: (p != preferred, p))
    for port in ports:
        health = _health(port)
        if health and not health.get("auth_required") and token_for(port):
            return port
    return None


def host_keys() -> list[str]:
    """Fingerprints of this server's SSH host keys, computed from the public files."""
    out = []
    for path in sorted(glob.glob("/etc/ssh/ssh_host_*_key.pub")):
        try:
            blob = base64.b64decode(open(path).read().split()[1])
        except (OSError, IndexError, ValueError):
            continue
        out.append("SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("="))
    return out


def _sshd_ports(path: str, depth: int = 0) -> list[int]:
    """`Port` values in the order sshd reads them, following `Include` (current distributions
    keep overrides in ``sshd_config.d/*.conf``). Keywords are case-insensitive, as in sshd."""
    out: list[int] = []
    try:
        with open(path) as f:
            lines = f.read().splitlines()
    except (OSError, UnicodeDecodeError):
        return out
    for line in lines:
        m = re.match(r"\s*port[\s=]+(\d{1,5})\s*(#.*)?$", line, re.I)
        if m:
            out.append(int(m.group(1)))
            continue
        m = re.match(r"\s*include[\s=]+(.+?)\s*$", line, re.I)
        if m and depth < 4:
            for pattern in m.group(1).split():
                if not os.path.isabs(pattern):
                    pattern = os.path.join(os.path.dirname(path), pattern)
                for included in sorted(glob.glob(pattern)):
                    out.extend(_sshd_ports(included, depth + 1))
    return out


def ssh_port(config: str = "/etc/ssh/sshd_config") -> int:
    override = os.environ.get("DOTPULSE_SSH_PORT", "")
    if override.isdigit() and 1 <= int(override) <= 65535:
        return int(override)
    ports = [p for p in _sshd_ports(config) if 1 <= p <= 65535]
    # sshd listens on every Port it is given; the first is as good as any, and what `ssh` would be told.
    return ports[0] if ports else 22


def host_is_explicit() -> bool:
    """True when the owner said where this server is (`DOTPULSE_HOST`), so it is not a guess."""
    return bool(os.environ.get("DOTPULSE_HOST", "").strip())


def public_host() -> str:
    """Where a phone should knock. `DOTPULSE_HOST` wins; otherwise the address this machine uses
    to reach the internet (no packet is sent: a UDP socket is only pointed at an address).
    Empty when there is no route at all; the caller says so instead of guessing."""
    override = os.environ.get("DOTPULSE_HOST", "").strip()
    if override:
        return override
    for family, probe in ((socket.AF_INET, "192.0.2.1"), (socket.AF_INET6, "2001:db8::1")):
        try:
            s = socket.socket(family, socket.SOCK_DGRAM)
        except OSError:
            continue
        try:
            s.connect((probe, 9))
            return s.getsockname()[0]
        except OSError:
            continue
        finally:
            s.close()
    return ""


def user() -> str:
    return getpass.getuser()
