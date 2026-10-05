"""What the two ends of a DotPulse link compute on their own: nothing here is sent to anyone as is.

A Pairing ID is 125 random bits. From it both ends derive, independently:

* ``lookup`` — what they show the Link service, so it can match them without learning the ID;
* ``key`` — which they never send. It authenticates each end's public key (``tag``) and yields the
  verification code a person compares. The service, which only ever saw ``lookup``, can forge neither.

After pairing, everything a stream carries is sealed with ChaCha20-Poly1305 under keys agreed with
X25519 (a fresh pair per session, mixed with the two long-lived keys exchanged during pairing).

Needs ``cryptography``, which Hermes already ships. The app implements the same in CryptoKit.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import struct

PREFIX = "DPP1"
#: Crockford Base32 without I, L, O, U.
ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
PATTERN = re.compile(r"DPP1-[0-9A-HJKMNP-TV-Z]{5}(?:-[0-9A-HJKMNP-TV-Z]{5}){4}")
#: Anything that looks like someone meant a Pairing ID, well formed or not.
MENTION = re.compile(r"\bDPP1-[0-9A-Za-z-]{4,}", re.I)
_WHOLE = re.compile(r"(?<![0-9A-Za-z-])" + PATTERN.pattern + r"(?![0-9A-Za-z-])", re.I)


def find(text: str) -> list:
    """Every distinct well-formed Pairing ID in ``text``, upper-cased, in order of appearance."""
    out = []
    for m in _WHOLE.finditer(text or ""):
        candidate = m.group(0).upper()
        if PATTERN.fullmatch(candidate) and candidate not in out:
            out.append(candidate)
    return out


def lookup(pairing_id: str) -> str:
    return hashlib.sha256(b"dotpulse-link/v1/lookup\n" + pairing_id.encode("ascii")).hexdigest()


def key(pairing_id: str) -> bytes:
    return hashlib.sha256(b"dotpulse-link/v1/key\n" + pairing_id.encode("ascii")).digest()


def tag(pairing_key: bytes, role: str, public_hex: str) -> str:
    """Proof that ``public_hex`` belongs to someone who holds the Pairing ID. ``role``: device | agent."""
    return hmac.new(pairing_key, ("%s\n%s" % (role, public_hex)).encode("ascii"), hashlib.sha256).hexdigest()


def tag_ok(pairing_key: bytes, role: str, public_hex: str, claimed: str) -> bool:
    return hmac.compare_digest(tag(pairing_key, role, public_hex), claimed or "")


def code(pairing_key: bytes, device_pub_hex: str, agent_pub_hex: str) -> str:
    """Six digits both screens show. It covers both public keys, so it only matches when the phone
    and this Hermes are looking at each other and nobody is in between."""
    digest = hmac.new(pairing_key, ("code\n%s\n%s" % (device_pub_hex, agent_pub_hex)).encode("ascii"), hashlib.sha256).digest()
    return "%06d" % (int.from_bytes(digest[:4], "big") % 1_000_000)


def spaced(code_: str) -> str:
    return code_[:3] + " " + code_[3:]


# ---------------------------------------------------------------------- keys and sessions

def new_private() -> str:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization as s
    return X25519PrivateKey.generate().private_bytes(s.Encoding.Raw, s.PrivateFormat.Raw, s.NoEncryption()).hex()


def public_of(private_hex: str) -> str:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization as s
    return X25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex)).public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw).hex()


def _dh(private_hex: str, public: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    return X25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex)).exchange(X25519PublicKey.from_public_bytes(public))


class Sealed(Exception):
    """A frame that did not open: wrong key, wrong order, or tampered with. The session is over."""


class Session:
    """One end of a sealed session. ``role`` is ``"device"`` or ``"agent"``.

    The device speaks first: ``hello()`` on its side, ``accept(hello)`` then ``hello()`` on the
    agent's, ``accept(hello)`` back on the device. After that ``seal`` and ``open`` work, each
    direction with its own key and a counter, so a frame replayed, dropped or reordered fails.
    """
    HELLO_LENGTH = 49

    def __init__(self, role: str, static_private_hex: str, peer_static_public_hex: str):
        self.role = role
        self._static = static_private_hex
        self._peer_static = bytes.fromhex(peer_static_public_hex)
        self._ephemeral = new_private()
        self._mine = (b"D" if role == "device" else b"A") + bytes.fromhex(public_of(self._ephemeral)) + os.urandom(16)
        self._send = self._recv = None
        self._sent = self._received = 0

    def hello(self) -> bytes:
        return self._mine

    @property
    def ready(self) -> bool:
        return self._send is not None

    def accept(self, theirs: bytes) -> None:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        expected = b"A" if self.role == "device" else b"D"
        if len(theirs) != self.HELLO_LENGTH or theirs[:1] != expected:
            raise Sealed("hello")
        device_hello, agent_hello = (self._mine, theirs) if self.role == "device" else (theirs, self._mine)
        try:
            shared = _dh(self._ephemeral, theirs[1:33]) + _dh(self._static, self._peer_static)
        except ValueError:
            raise Sealed("hello")
        okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=hashlib.sha256(device_hello + agent_hello).digest(),
                   info=b"dotpulse-link/v1/e2e").derive(shared)
        to_agent, to_device = ChaCha20Poly1305(okm[:32]), ChaCha20Poly1305(okm[32:])
        self._send, self._recv = (to_agent, to_device) if self.role == "device" else (to_device, to_agent)
        self._sent = self._received = 0

    def seal(self, kind: int, stream: int, data: bytes) -> bytes:
        nonce = b"\0\0\0\0" + struct.pack(">Q", self._sent)
        self._sent += 1
        return self._send.encrypt(nonce, data, struct.pack(">BI", kind, stream))

    def open(self, kind: int, stream: int, data: bytes) -> bytes:
        from cryptography.exceptions import InvalidTag
        nonce = b"\0\0\0\0" + struct.pack(">Q", self._received)
        try:
            plain = self._recv.decrypt(nonce, data, struct.pack(">BI", kind, stream))
        except InvalidTag:
            raise Sealed("frame")
        self._received += 1
        return plain
