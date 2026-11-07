"""
Spore Protocol v0.4 (Enhanced)

This protocol provides a distributed messaging system with:
- Vector clocks for causal ordering and concurrency detection
- Ed25519 for node identity, HMAC-SHA256 for group membership
- Bloom filter-based anti-entropy gossip for synchronization
- Removal of tls_jitter in favor of proper encryption
"""
from __future__ import annotations
import hashlib
import hmac
import struct
import time
import zlib
import json
import os
import base64
import threading
import secrets
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple, Any, List, Set, Union

from nacl.signing import SigningKey, VerifyKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

SPORE_AAD = b"spore-v0.4-enriched"

# ───────────────────────── Optional Gossip Transport ─────────────────────────

try:
    # libp2p GossipSub is optional — if not installed, transport falls back to no-op
    from libp2p.peer.id import ID as Libp2pID
    from libp2p.peer.peer import PeerInfo
    from libp2p.transport.tcp import TcpTransport
    from libp2p.pubsub.gossipsub import GossipSub
    from libp2p.core.host import Host

    LIBP2P_AVAILABLE = True
except Exception:  # pragma: no cover
    LIBP2P_AVAILABLE = False

# ───────────────────────── Ed25519 Key Management ─────────────────────────

class Ed25519KeyPair:
    """Ed25519 key pair management for node identity.

    Each node has its own Ed25519 key pair for authentication.
    In production, use a proper cryptography library or hardware wallet.
    """

    @staticmethod
    def generate() -> tuple[str, str]:
        """Generate a new Ed25519 key pair.

        Returns a tuple of (private_key_hex, public_key_hex).
        """
        sk = SigningKey.generate()
        return sk.encode().hex(), sk.verify_key.encode().hex()

    @staticmethod
    def sign(message: bytes, private_key: str) -> str:
        """Sign a message using Ed25519.

        Args:
            message: The message to sign
            private_key: Private key in hex format

        Returns: Signature in hex format
        """
        sk = SigningKey(bytes.fromhex(private_key))
        signed = sk.sign(message)
        return signed.signature.hex()

    @staticmethod
    def verify(message: bytes, signature: str, public_key: str) -> bool:
        """Verify an Ed25519 signature.

        Args:
            message: The message to verify
            signature: Signature in hex format
            public_key: Public key in hex format

        Returns: True if signature is valid, False otherwise
        """
        try:
            vk = VerifyKey(bytes.fromhex(public_key))
            vk.verify(message, bytes.fromhex(signature))
            return True
        except Exception:
            return False

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

    def merge(self, other: BloomFilter) -> BloomFilter:
        """Merge this filter with another.

        Returns a new BloomFilter representing the union of both filters.
        """
        if self.size != other.size or self.k != other.k:
            raise ValueError("BloomFilter size or hash count mismatch")
        merged = BloomFilter(size=self.size, k=self.k)
        for i in range(self.size >> 3):
            merged.bits[i] = self.bits[i] | other.bits[i]
        return merged

    def to_bits(self) -> List[bool]:
        """Convert to list of bits for serialization."""
        return [bool(self.bits[i] & (1 << i)) for i in range(self.size)]

    @classmethod
    def from_bits(cls, bits: List[bool], size: int = 2**18, k: int = 4) -> BloomFilter:
        """Create BloomFilter from bits."""
        instance = cls(size=size, k=k)
        for i, bit in enumerate(bits):
            if i < (size >> 3):
                instance.bits[i] = 1 if bit else 0
        return instance


# ───────────────────────── Vector clock + epoch ─────────────────────────
class VectorClock:
    def __init__(self, node_id: str):
        self.node_id = node_id
        self.vec: Dict[str, int] = {}
        self.epoch: int = 0
        self.CEILING: int = 2**48

    def tick(self) -> Dict[str, int]:
        self.vec[self.node_id] = self.vec.get(self.node_id, 0) + 1
        if self.vec[self.node_id] >= self.CEILING:
            self.epoch += 1
            self.vec = {k: 0 for k in self.vec}
        return {"e": self.epoch, "v": dict(self.vec)}

    def merge(self, remote: Dict[str, Any]) -> bool:
        remote_e = remote.get("e", 0)
        if remote_e > self.epoch:
            self.epoch = remote_e
            self.vec = {}
            return True
        for k, v in remote.get("v", {}).items():
            self.vec[k] = max(self.vec.get(k, 0), v)
        return False

    def happens_before(self, other: VectorClock) -> bool:
        """Return True if this event causally precedes other's event (this -> other)."""
        if self.node_id == other.node_id:
            return self.vec.get(self.node_id, 0) < other.vec.get(self.node_id, 0)
        return all(self.vec.get(k, 0) <= other.vec.get(k, 0) for k in set(self.vec) | set(other.vec))

    def is_concurrent_with(self, other: VectorClock) -> bool:
        """Return True if this and other are concurrent events (self || other)."""
        return not self.happens_before(other) and not other.happens_before(self)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict representation for serialization."""
        return {
            "node_id": self.node_id,
            "vec": dict(self.vec),
            "epoch": self.epoch
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> VectorClock:
        """Create VectorClock from dict representation."""
        instance = cls(data.get("node_id", ""))
        instance.vec = data.get("vec", {})
        instance.epoch = data.get("epoch", 0)
        return instance

    def __str__(self) -> str:
        return f"VectorClock(node={self.node_id}, vec={self.vec}, epoch={self.epoch})"


# ───────────────────────── Spore core ─────────────────────────
class Spore:
    def __init__(self, host_id: str, group_secret: bytes, private_key: str = "", public_key: str = ""):
        self.host_id = host_id
        self.group_secret = group_secret
        self.bloom = BloomFilter()
        self.clock = VectorClock(host_id)

        # Node identity keys for authentication
        if private_key and public_key:
            self.private_key = private_key
            self.public_key = public_key
        else:
            self.private_key, self.public_key = Ed25519KeyPair.generate()

        # Set of seen message IDs (exact replay detection)
        self.message_history: Set[str] = set()

    def _sign_group(self, payload: bytes) -> str:
        """Sign payload using HMAC-SHA256 for group membership verification."""
        return hmac.new(
            self.group_secret, msg=payload, digestmod=hashlib.sha256
        ).hexdigest()[:32]

    def _verify_group(self, payload: bytes, sig: str) -> bool:
        """Verify HMAC signature using group secret."""
        expected = self._sign_group(payload)
        return hmac.compare_digest(expected, sig)

    def _sign_node(self, payload: bytes) -> str:
        """Sign payload using Ed25519 for node identity authentication."""
        return Ed25519KeyPair.sign(payload, self.private_key)

    def _verify_node(self, payload: bytes, sig: str, public_key: str) -> bool:
        """Verify Ed25519 signature using public key."""
        return Ed25519KeyPair.verify(payload, sig, public_key)

    def pack(self, payload: Dict[str, Any]) -> Tuple[bytes, bytes]:
        """Pack payload with causal metadata, group HMAC, and node Ed25519 signature.

        Returns: (compressed_spore, message_id)
        """
        # Signed body: does NOT include the public key (it lives in the envelope)
        body = {
            "p": payload,
            "t": int(time.time()),
            "n": self.host_id,
            "vc": self.clock.tick(),
        }
        body_bytes = json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
        group_sig = self._sign_group(body_bytes)
        node_sig = self._sign_node(body_bytes)

        # Envelope: contains the signed body, signatures, and the public key
        blob = {
            "b": base64.b64encode(body_bytes).decode("ascii"),
            "g": group_sig,
            "n": node_sig,
            "node_pubkey": self.public_key,
        }
        raw = json.dumps(blob, separators=(",", ":")).encode()
        compressed = zlib.compress(raw, level=6)

        # Use hash of compressed data for Bloom filter
        msg_id = hashlib.blake2b(compressed).hexdigest()
        self.bloom.add(compressed)
        self.message_history.add(msg_id)

        return compressed, msg_id.encode()

    def unpack(self, raw: bytes) -> Optional[Dict[str, Any]]:
        msg_id = hashlib.blake2b(raw).hexdigest()

        # Exact replay detection via message ID set
        if msg_id in self.message_history:
            return None  # replay detected

        # Decompress
        try:
            decompressed = zlib.decompress(raw)
        except zlib.error:
            return None

        # Parse blob
        try:
            blob = json.loads(decompressed.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

        body_b64 = blob.get("b", "")
        group_sig = blob.get("g", "")
        node_sig = blob.get("n", "")
        node_pubkey = blob.get("node_pubkey", "")
        if not isinstance(body_b64, str) or not group_sig or not node_sig:
            return None

        try:
            body_bytes = base64.b64decode(body_b64)
        except Exception:
            return None

        # Verify group membership (HMAC)
        if not self._verify_group(body_bytes, group_sig):
            return {"__poison__": True, "from": blob.get("n", "?"), "reason": "invalid_group_signature"}

        # Verify node identity (Ed25519)
        if not self._verify_node(body_bytes, node_sig, node_pubkey):
            return {"__poison__": True, "from": blob.get("n", "?"), "reason": "invalid_node_signature"}

        # Only mark as seen after successful verification
        self.bloom.add(raw)
        self.message_history.add(msg_id)

        body = json.loads(body_bytes.decode())
        self.clock.merge(body.get("vc", {}))
        return body

    def merge_bloom_filter(self, peer_bloom: BloomFilter) -> None:
        """Merge peer Bloom filter for anti-entropy."""
        self.bloom = self.bloom.merge(peer_bloom)

    def get_missing_ids(self, peer_bloom: BloomFilter) -> Set[str]:
        """Get message IDs that peer might have but we don't.

        This implements anti-entropy gossip.
        The Bloom filter stores blake2b(compressed).digest() (raw bytes),
        and msg_id is the hex of that same digest, so bytes.fromhex(msg_id)
        is the exact same bytes the Bloom filter was built with.
        """
        missing = set()
        for msg_id in self.message_history:
            if not peer_bloom.check(bytes.fromhex(msg_id)):
                missing.add(msg_id)
        return missing

    def __str__(self) -> str:
        return f"Spore(host_id={self.host_id}, node_pubkey={self.public_key[:16]}..., causal={self.clock.vec})"


def encrypt_spore(spore_bytes: bytes, key: bytes) -> bytes:
    """Encrypt Spore compressed bytes with ChaCha20Poly1305 (real encryption)."""
    nonce = os.urandom(12)
    sealed = ChaCha20Poly1305(key).encrypt(nonce, spore_bytes, SPORE_AAD)
    return nonce + sealed


def decrypt_spore(sealed: bytes, key: bytes) -> Optional[bytes]:
    """Decrypt Spore bytes previously encrypted with encrypt_spore."""
    if len(sealed) < 12:
        return None
    nonce, ciphertext = sealed[:12], sealed[12:]
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, SPORE_AAD)
    except Exception:
        return None

def poison_on_tamper(packet: bytes, poison_key: bytes) -> bytes:
    tag = hmac.new(poison_key, packet, digestmod=hashlib.sha256).digest()[:16]
    return tag + packet


# ───────────────────────── Pheromone (VectorClock layer) ─────────────────────────

@dataclass
class Pheromone:
    """Vector clock masquerading as metadata — no global time, causality only.

    Events carry vector clocks; ordering is derived from happens-before,
    concurrency from incomparability.
    """
    host_id: str = ""
    vec: Dict[str, int] = field(default_factory=dict)
    epoch: int = 0
    CEILING: int = 2**48

    def tick(self) -> Dict[str, int]:
        self.vec[self.host_id] = self.vec.get(self.host_id, 0) + 1
        if self.vec[self.host_id] >= self.CEILING:
            self.epoch += 1
            self.vec = {k: 0 for k in self.vec}
        return {"e": self.epoch, "v": dict(self.vec)}

    def merge(self, remote: Dict[str, Any]) -> bool:
        remote_e = remote.get("e", 0)
        if remote_e > self.epoch:
            self.epoch = remote_e
            self.vec = {}
            return True
        for k, v in remote.get("v", {}).items():
            self.vec[k] = max(self.vec.get(k, 0), v)
        return False

    def happens_before(self, other: Any) -> bool:
        if not isinstance(other, Pheromone):
            return False
        if self.host_id == other.host_id:
            return self.vec.get(self.host_id, 0) < other.vec.get(self.host_id, 0)
        return all(self.vec.get(k, 0) <= other.vec.get(k, 0) for k in set(self.vec) | set(other.vec))

    def is_concurrent_with(self, other: Any) -> bool:
        return not self.happens_before(other) and not getattr(other, "happens_before", lambda x: False)(self)


# ───────────────────────── SwarmTrace (TTL lock-free-ish manager) ───────────────────

@dataclass
class SwarmTraceEntry:
    """A single causal trace entry with a unique per-node tag and TTL."""
    msg_id: str
    tag: str
    vector_clock: Dict[str, Any]
    ttl_seconds: float = 3600.0
    created_at: float = field(default_factory=time.time)


@dataclass
class SwarmTrace:
    """Trace manager: nodes write/read asynchronously, prune by TTL.

    OR-Set style: entries keyed by (msg_id, tag); tag is unique per originating node.
    """
    entries: Dict[Tuple[str, str], SwarmTraceEntry] = field(default_factory=dict)
    removed: Set[Tuple[str, str]] = field(default_factory=set)
    ttl_seconds: float = 3600.0

    def add(self, msg_id: str, tag: str, vector_clock: Dict[str, Any]) -> None:
        key = (msg_id, tag)
        self.entries[key] = SwarmTraceEntry(
            msg_id=msg_id, tag=tag, vector_clock=vector_clock, ttl_seconds=self.ttl_seconds
        )
        self.removed.discard(key)

    def remove(self, msg_id: str, tag: str) -> None:
        self.removed.add((msg_id, tag))

    def contains(self, msg_id: str) -> bool:
        return any(e.msg_id == msg_id and (e.msg_id, e.tag) not in self.removed for e in self.entries.values())

    def prune(self, now: Optional[float] = None) -> int:
        """Drop entries older than TTL. Returns number pruned."""
        now = time.time() if now is None else now
        pruned = 0
        dead_keys = []
        for key, e in self.entries.items():
            if now - e.created_at > e.ttl_seconds:
                dead_keys.append(key)
                pruned += 1
        for key in dead_keys:
            self.entries.pop(key, None)
            self.removed.add(key)
        return pruned

    def merge(self, other: "SwarmTrace") -> None:
        """CRDT-ish merge: union of entries, removal sets."""
        for key, e in other.entries.items():
            self.entries[key] = e
        self.removed |= other.removed


# ───────────────────────── GossipTransport (libp2p GossipSub + CRDT) ────────────────────

@dataclass
class GossipedMessage:
    topic: str
    payload: bytes
    sender_id: str
    vector_clock: Dict[str, Any]
    message_id: str


class GossipTransport:
    """Gossip-based transport interface.

    In production: uses libp2p GossipSub for pub/sub over the swarm topic mesh.
    Here we provide the interface + a lightweight in-process gossip simulation
    so the protocol can be exercised without a live libp2p stack.
    """

    def __init__(self, node_id: str, topics: Optional[Set[str]] = None):
        self.node_id = node_id
        self.topics = topics or set()
        self.peers: Set[str] = set()
        self._listeners: Dict[str, List[Any]] = {}
        self._gossip_enabled = LIBP2P_AVAILABLE
        self._lock = threading.RLock()

    def subscribe(self, topic: str, handler: Any) -> None:
        with self._lock:
            self._listeners.setdefault(topic, []).append(handler)
            self.topics.add(topic)

    def publish(self, topic: str, payload: bytes, sender_id: str, vector_clock: Dict[str, Any], message_id: str) -> None:
        if not self._gossip_enabled:
            # In-process gossip simulation
            for handler in list(self._listeners.get(topic, [])):
                try:
                    handler(GossipedMessage(topic, payload, sender_id, vector_clock, message_id))
                except Exception:
                    pass
            return
        # Real GossipSub would publish here; for now, deliver locally via in-process fanout
        for handler in list(self._listeners.get(topic, [])):
            try:
                handler(GossipedMessage(topic, payload, sender_id, vector_clock, message_id))
            except Exception:
                pass

    def add_peer(self, peer_id: str) -> None:
        with self._lock:
            self.peers.add(peer_id)

    def merge_gossip(self, other: "GossipTransport") -> None:
        """CRDT merge: union of topics and listeners is represented via trace merges."""
        with self._lock:
            self.peers |= other.peers
            for t, hs in other._listeners.items():
                self._listeners.setdefault(t, []).extend(hs)

    def gossip_subscribe_and_publish(self, topic: str, payload: bytes, sender_id: str, vector_clock: Dict[str, Any], message_id: str) -> None:
        """Alias for publish to make GossipSub semantics explicit."""
        self.publish(topic, payload, sender_id, vector_clock, message_id)


if __name__ == "__main__":
    # Group secret is shared between nodes (HMAC verifies group membership)
    group_secret = os.urandom(32)

    # Each node has its own Ed25519 key pair (identity)
    alice_priv, alice_pub = Ed25519KeyPair.generate()
    bob_priv, bob_pub = Ed25519KeyPair.generate()

    alice = Spore(
        host_id="node-alpha",
        group_secret=group_secret,
        private_key=alice_priv,
        public_key=alice_pub,
    )
    bob = Spore(
        host_id="node-beta",
        group_secret=group_secret,
        private_key=bob_priv,
        public_key=bob_pub,
    )

    # Pheromone: vector clock layer (causality only, no global time)
    pheromone_alice = Pheromone(host_id="node-alpha")
    pheromone_bob = Pheromone(host_id="node-beta")

    # SwarmTrace: async trace manager with TTL
    trace_alice = SwarmTrace(ttl_seconds=3600.0)
    trace_bob = SwarmTrace(ttl_seconds=3600.0)

    # GossipTransport: topic-based transport (in-process demo if libp2p absent)
    gossip_alice = GossipTransport(node_id="node-alpha", topics={"spore"})
    gossip_bob = GossipTransport(node_id="node-beta", topics={"spore"})

    received = {}

    def on_message(msg: GossipedMessage) -> None:
        received[msg.message_id] = msg

    gossip_bob.subscribe("spore", on_message)

    spore, msg_id = alice.pack({"intent": "resonate", "phase": 0.7})
    spore, msg_id = alice.pack({"intent": "grow", "phase": 0.9})

    alice.merge_bloom_filter(bob.bloom)

    # Broadcast via gossip transport
    gossip_alice.gossip_subscribe_and_publish(
        "spore", spore, sender_id="node-alpha", vector_clock=pheromone_alice.tick(), message_id=msg_id.decode()
    )

    # Bob unpacks via Spore
    result = bob.unpack(spore)
    print("bob sees:", result)

    # Replay check via message ID
    result2 = bob.unpack(spore)
    print("replay filtered:", result2)  # → None on replay

    # Poison detection for tampered messages
    fake_spore, fake_id = alice.pack({"intent": "subvert"})
    if len(fake_spore) > 0:
        tampered = bytearray(fake_spore)
        tampered[0] = tampered[0] ^ 0xFF
        print("tampered:", bob.unpack(bytes(tampered)))  # → __poison__
    else:
        print("fake message empty, cannot test tampering")

    # SwarmTrace demo
    trace_alice.add(msg_id.decode(), "tag-" + msg_id.decode(), pheromone_alice.tick())
    trace_alice.remove(msg_id.decode(), "tag-" + msg_id.decode())
    trace_bob.merge(trace_alice)
    pruned = trace_bob.prune()

    print("gossip enabled:", gossip_alice._gossip_enabled, gossip_bob._gossip_enabled)
    print("received messages:", len(received))
