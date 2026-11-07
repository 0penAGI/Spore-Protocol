"""
Spore Protocol v0.4
"""
import hashlib
import hmac
import struct
import time
import zlib
import json
import os
import base64
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple, Any


# ───────────────────────── Bloom pre-filter ─────────────────────────
class BloomFilter:
    def __init__(self, size: int = 2**18, k: int = 4):
        self.size = size
        self.k = k
        self.bits = bytearray(size >> 3)

    def _hashes(self, data: bytes):
        h = hashlib.blake2b(data).digest()
        h1, h2 = struct.unpack("<QQ", h[:16])
        for i in range(self.k):
            yield (h1 + i * h2) % self.size

    def add(self, data: bytes):
        for bit in self._hashes(data):
            self.bits[bit >> 3] |= 1 << (bit & 7)

    def check(self, data: bytes) -> bool:
        return all(self.bits[b >> 3] & (1 << (b & 7)) for b in self._hashes(data))


# ───────────────────────── Vector clock + epoch ─────────────────────────
@dataclass
class VectorClock:
    node_id: str
    vec: Dict[str, int] = field(default_factory=dict)
    epoch: int = 0
    CEILING: int = 2**48

    def tick(self) -> Dict[str, int]:
        self.vec[self.node_id] = self.vec.get(self.node_id, 0) + 1
        if self.vec[self.node_id] >= self.CEILING:
            self.epoch += 1
            self.vec = {k: 0 for k in self.vec}
        return {"e": self.epoch, "v": dict(self.vec)}

    def merge(self, remote: Dict[str, Any]):
        if remote.get("e", 0) > self.epoch:
            self.epoch = remote["e"]
            self.vec = {}
        for k, v in remote.get("v", {}).items():
            self.vec[k] = max(self.vec.get(k, 0), v)


# ───────────────────────── Spore core ─────────────────────────
@dataclass
class Spore:
    host_id: str
    secret: bytes
    bloom: BloomFilter = field(default_factory=BloomFilter)
    clock: VectorClock = field(default_factory=lambda: VectorClock(""))

    def __post_init__(self):
        self.clock.node_id = self.host_id

    # ── подпись на секрете хоста (растворяется в jitter) ──
    def _sign(self, payload: bytes) -> str:
        return hmac.new(
            self.secret, msg=payload, digestmod=hashlib.sha256
        ).hexdigest()[:32]

    def _verify(self, payload: bytes, sig: str) -> bool:
        expected = self._sign(payload)
        return hmac.compare_digest(expected, sig)

    # ── pack: payload → blob с подписью и вектором ──
    def pack(self, payload: Dict[str, Any]) -> bytes:
        body = {
            "p": payload,
            "t": int(time.time()),
            "n": self.host_id,
            "vc": self.clock.tick(),
        }
        body_bytes = json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
        sig = self._sign(body_bytes)
        
        blob = {
            "b": base64.b64encode(body_bytes).decode("ascii"),
            "s": sig
        }
        raw = json.dumps(blob, separators=(",", ":")).encode()
        compressed = zlib.compress(raw, level=6)
        
        self.bloom.add(hashlib.blake2b(compressed).digest())
        return compressed

    def unpack(self, raw: bytes) -> Optional[Dict[str, Any]]:
        # 1. pre-filter: bloom на сжатых данных (как в pack)
        if self.bloom.check(hashlib.blake2b(raw).digest()):
            return None  # replay / дубликат
        self.bloom.add(hashlib.blake2b(raw).digest())

        # 2. decompress
        try:
            decompressed = zlib.decompress(raw)
        except zlib.error:
            return None

        # 3. parse
        try:
            blob = json.loads(decompressed.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

        body_b64 = blob.get("b", "")
        sig = blob.get("s", "")
        if not isinstance(body_b64, str) or not sig:
            return None

        try:
            body_bytes = base64.b64decode(body_b64)
        except Exception:
            return None

        if not self._verify(body_bytes, sig):
            return {"__poison__": True, "from": blob.get("n", "?")}

        body = json.loads(body_bytes.decode())
        self.clock.merge(body.get("vc", {}))
        return body


def wrap_as_tls_jitter(spore_bytes: bytes) -> bytes:
    header = bytes([0x17, 0x03, 0x03]) + struct.pack(">H", len(spore_bytes))
    return header + spore_bytes


def unwrap_tls_jitter(packet: bytes) -> Optional[bytes]:
    if len(packet) < 5:
        return None
    if packet[0] != 0x17 or packet[1] != 0x03 or packet[2] != 0x03:
        return None
    length = struct.unpack(">H", packet[3:5])[0]
    return packet[5 : 5 + length]

def poison_on_tamper(packet: bytes, poison_key: bytes) -> bytes:
    tag = hmac.new(poison_key, packet, digestmod=hashlib.sha256).digest()[:16]
    return tag + packet

if __name__ == "__main__":
    alice = Spore(host_id="node-alpha", secret=os.urandom(32))
    bob = Spore(host_id="node-beta", secret=alice.secret)  

    spore = alice.pack({"intent": "resonate", "phase": 0.7})
    packet = wrap_as_tls_jitter(spore)

    inner = unwrap_tls_jitter(packet)
    result = bob.unpack(inner)
    print("bob sees:", result)

    fake = alice.pack({"intent": "subvert"})
    tampered = fake[:-4] + b"\x00\x00\x00\x00"  
    print("tampered:", bob.unpack(tampered))  # → __poison__
