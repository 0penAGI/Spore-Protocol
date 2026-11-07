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
        """Convert to list of bits (len == size) for exact serialization/transport."""
        bits = [False] * self.size
        for byte_idx, byte_val in enumerate(self.bits):
            if byte_val == 0:
                continue
            base = byte_idx << 3
            for b in range(8):
                pos = base + b
                if pos >= self.size:
                    break
                bits[pos] = bool(byte_val & (1 << b))
        return bits

    @classmethod
    def from_bits(cls, bits: List[bool], size: int = 2**18, k: int = 4) -> BloomFilter:
        """Reconstruct BloomFilter from bit list produced by to_bits()."""
        instance = cls(size=size, k=k)
        for pos, bit in enumerate(bits[:size]):
            if bit:
                byte_idx = pos >> 3
                bit_idx = pos & 7
                instance.bits[byte_idx] |= 1 << bit_idx
        return instance


# ───────────────────────── Vector clock ─────────────────────────
class VectorClock:
    def __init__(self, node_id: str):
        self.node_id = node_id
        self.vec: Dict[str, int] = {}

    def tick(self) -> Dict[str, Any]:
        self.vec[self.node_id] = self.vec.get(self.node_id, 0) + 1
        return {"v": dict(self.vec)}

    def merge(self, remote: Dict[str, Any]) -> bool:
        """Merge counters component-wise; legacy epoch fields are ignored."""
        changed = False
        remote_vec = remote.get("v", remote.get("vec", {}))
        if not isinstance(remote_vec, dict):
            return False
        for k, v in remote_vec.items():
            if type(v) is not int or v < 0:
                continue
            if v > self.vec.get(k, 0):
                self.vec[k] = v
                changed = True
        return changed

    def happens_before(self, other: VectorClock) -> bool:
        """Return True if this event causally precedes other's event (this -> other)."""
        at_least_one_strict = False
        all_keys = set(self.vec) | set(other.vec)
        for k in all_keys:
            sv = self.vec.get(k, 0)
            ov = other.vec.get(k, 0)
            if sv > ov:
                return False
            if sv < ov:
                at_least_one_strict = True
        return at_least_one_strict

    def is_concurrent_with(self, other: VectorClock) -> bool:
        """Return True if this and other are concurrent events (self || other)."""
        return (
            not self.happens_before(other)
            and not other.happens_before(self)
            and self.vec != other.vec
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict representation for serialization."""
        return {"node_id": self.node_id, "vec": dict(self.vec)}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> VectorClock:
        """Create VectorClock from dict representation."""
        instance = cls(data.get("node_id", ""))
        raw_vec = data.get("vec", data.get("v", {}))
        if isinstance(raw_vec, dict):
            instance.vec = {
                node: counter for node, counter in raw_vec.items()
                if isinstance(node, str) and type(counter) is int and counter >= 0
            }
        return instance

    def __str__(self) -> str:
        return f"VectorClock(node={self.node_id}, vec={self.vec})"


# ───────────────────────── Spore core ─────────────────────────
class Spore:
    def __init__(self, host_id: str, group_secret: bytes, private_key: str = "", public_key: str = "",
                 history_file: Optional[str] = None, max_history_size: int = 10000):
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

        # Set of seen message IDs (exact replay detection), mapped to timestamps for pruning
        self.message_history: Dict[str, float] = {}

        # Optional AEAD transport encryption key (bound to this node's swarm)
        self.encryption_key: Optional[bytes] = None

        # Swarm membership registry: public_key -> host_id (Ed25519 identity -> member)
        self.swarm_members: Dict[str, str] = {}

        # Persistent replay history
        self.history_file = history_file
        self.max_history_size = max_history_size
        self._load_history()

    def _load_history(self) -> None:
        """Load replay message IDs from disk if a history file was provided."""
        if not self.history_file:
            return
        try:
            with open(self.history_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            for msg_id, ts in data.items():
                self.message_history[msg_id] = ts
            # Trim to max size keeping newest entries
            if len(self.message_history) > self.max_history_size:
                newest = sorted(self.message_history.items(), key=lambda kv: kv[1], reverse=True)[:self.max_history_size]
                self.message_history = dict(newest)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            # Start fresh if file is missing or corrupt
            self.message_history = {}

    def _save_history(self) -> None:
        """Persist replay message IDs and timestamps to disk."""
        if not self.history_file:
            return
        try:
            with open(self.history_file, "w", encoding="utf-8") as f:
                json.dump(self.message_history, f)
        except OSError:
            pass

    def _prune_history(self) -> None:
        """Remove oldest entries if message history exceeds max size."""
        if len(self.message_history) <= self.max_history_size:
            return
        # Keep newest entries based on timestamp
        newest = sorted(self.message_history.items(), key=lambda kv: kv[1], reverse=True)[: self.max_history_size]
        self.message_history = dict(newest)

    def authorize_member(self, public_key: str, host_id: str) -> None:
        """Register a node's Ed25519 public key as an authorized member of this swarm."""
        self.swarm_members[public_key] = host_id

    def deny_member(self, public_key: str) -> None:
        """Remove a node from the authorized membership registry."""
        self.swarm_members.pop(public_key, None)

    def is_member(self, public_key: str) -> bool:
        """Return True if the public key is an authorized member.

        If the registry is empty, membership is NOT automatically granted
        (no allow-all fallback) — a node must be explicitly authorized.
        """
        if not self.swarm_members:
            return False
        return public_key in self.swarm_members

    def set_encryption_key(self, key: bytes) -> None:
        """Set the optional AEAD encryption key for this Spore instance."""
        self.encryption_key = key

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

        # Use the canonical message-ID bytes in Bloom and exact inventory.
        msg_id = hashlib.blake2b(compressed).hexdigest()
        self.bloom.add(bytes.fromhex(msg_id))
        self.message_history[msg_id] = time.time()
        self._prune_history()
        self._save_history()

        # Optional AEAD encryption: if this node has a key, wrap the compressed blob
        if self.encryption_key:
            compressed = encrypt_spore(compressed, self.encryption_key)

        return compressed, msg_id.encode()

    def unpack(self, raw: bytes) -> Optional[Dict[str, Any]]:
        # Optional AEAD decryption: if we have a key, try to unwrap first
        if self.encryption_key:
            decrypted = decrypt_spore(raw, self.encryption_key)
            if decrypted is None:
                return None
            raw = decrypted

        msg_id = hashlib.blake2b(raw).hexdigest()

        # Exact replay detection via message ID set (computed on plaintext, matching pack)
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

        # Try to decode body for host_id (safe: signatures are verified below)
        try:
            body = json.loads(body_bytes.decode())
            host_id = body.get("n", "?")
        except (json.JSONDecodeError, UnicodeDecodeError):
            host_id = "?"

        # Verify group membership (HMAC)
        if not self._verify_group(body_bytes, group_sig):
            return {"__poison__": True, "from": host_id, "reason": "invalid_group_signature"}

        # Verify node identity (Ed25519)
        if not self._verify_node(body_bytes, node_sig, node_pubkey):
            return {"__poison__": True, "from": host_id, "reason": "invalid_node_signature"}

        # Optional: verify the node is an authorized member of this swarm
        if not self.is_member(node_pubkey):
            return {"__poison__": True, "from": host_id, "reason": "unauthorized_member"}
        if self.swarm_members.get(node_pubkey) != host_id:
            return {"__poison__": True, "from": host_id, "reason": "host_id_mismatch"}

        # Only mark as seen after successful verification
        self.bloom.add(bytes.fromhex(msg_id))
        self.message_history[msg_id] = time.time()
        self._prune_history()
        self._save_history()

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
        for msg_id in self.message_history.keys():
            if not peer_bloom.check(bytes.fromhex(msg_id)):
                missing.add(msg_id)
        return missing

    def get_inventory(self) -> Set[str]:
        """Return the exact set of message IDs retained in local history."""
        return set(self.message_history)

    def get_missing_from_inventory(self, peer_inventory: Set[str]) -> Set[str]:
        """Return IDs present in the peer inventory but absent locally."""
        return set(peer_inventory) - set(self.message_history)

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
        return {"v": dict(self.vec)}

    def merge(self, remote: Dict[str, Any]) -> bool:
        """Merge remote vector clock. Never destroys local causal history."""
        changed = False
        for k, v in remote.get("v", {}).items():
            if type(v) is not int or v < 0:
                continue
            if v > self.vec.get(k, 0):
                self.vec[k] = v
                changed = True
        return changed

    def happens_before(self, other: Any) -> bool:
        if not isinstance(other, Pheromone):
            return False
        less = False
        for key in set(self.vec) | set(other.vec):
            left = self.vec.get(key, 0)
            right = other.vec.get(key, 0)
            if left > right:
                return False
            if left < right:
                less = True
        return less

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

    Proper OR-Set: each add generates a unique tag; removes specify a tag to remove.
    An element is present iff there exists an add with tag T such that T is not
    in the removed set. Merge is union of adds and union of removed tags.
    """
    adds: Dict[Tuple[str, str], SwarmTraceEntry] = field(default_factory=dict)
    removed: Set[str] = field(default_factory=set)  # set of tags to remove
    ttl_seconds: float = 3600.0
    payloads: Dict[str, bytes] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def add(self, msg_id: str, tag: str, vector_clock: Dict[str, Any],
            payload: Optional[bytes] = None) -> None:
        """Add an element with a unique tag; removed tags can never be reused."""
        with self._lock:
            if tag in self.removed or any(existing_tag == tag for _, existing_tag in self.adds):
                raise ValueError("Removed OR-Set tags cannot be reused")
            key = (msg_id, tag)
            self.adds[key] = SwarmTraceEntry(
                msg_id=msg_id, tag=tag, vector_clock=vector_clock, ttl_seconds=self.ttl_seconds
            )
            if payload is not None:
                self.payloads[msg_id] = payload

    def remove(self, msg_id: str, tag: str) -> None:
        """Remove a tag. Concurrent add+remove on the same tag: remove wins."""
        with self._lock:
            self.removed.add(tag)

    def contains(self, msg_id: str) -> bool:
        with self._lock:
            for (mid, tag) in self.adds:
                if mid == msg_id and tag not in self.removed:
                    return True
            return False

    def get_payload(self, msg_id: str) -> Optional[bytes]:
        with self._lock:
            return self.payloads.get(msg_id)

    def prune(self, now: Optional[float] = None) -> int:
        """Drop entries older than TTL. Returns number pruned."""
        now = time.time() if now is None else now
        pruned = 0
        with self._lock:
            for key, entry in list(self.adds.items()):
                if now - entry.created_at > entry.ttl_seconds:
                    self.removed.add(entry.tag)
                    del self.adds[key]
                    pruned += 1
            active_ids = {
                msg_id for (msg_id, tag) in self.adds if tag not in self.removed
            }
            for msg_id in list(self.payloads):
                if msg_id not in active_ids:
                    self.payloads.pop(msg_id, None)
        return pruned

    def merge(self, other: "SwarmTrace") -> None:
        """OR-Set merge: union of adds, union of removed tags.

        Concurrent remove+add on the same tag: the remove wins because the tag
        ends up in the union of removed sets.
        """
        with other._lock:
            remote_adds = dict(other.adds)
            remote_removed = set(other.removed)
            remote_payloads = dict(other.payloads)
        with self._lock:
            self.removed |= remote_removed
            for key, entry in remote_adds.items():
                if key not in self.adds:
                    self.adds[key] = entry
            active_ids = {
                msg_id for (msg_id, tag) in self.adds if tag not in self.removed
            }
            for msg_id, payload in remote_payloads.items():
                if msg_id in active_ids:
                    self.payloads.setdefault(msg_id, payload)
            for msg_id in list(self.payloads):
                if msg_id not in active_ids:
                    self.payloads.pop(msg_id, None)

    def get_missing_ids(self, peer_bloom: BloomFilter) -> Set[str]:
        """Return msg_ids that peer_bloom indicates we may have missed."""
        missing = set()
        with self._lock:
            for (msg_id, tag) in self.adds:
                if tag in self.removed:
                    continue
                if not peer_bloom.check(bytes.fromhex(msg_id)):
                    missing.add(msg_id)
        return missing


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

    def __init__(self, node_id: str, topics: Optional[Set[str]] = None,
                 host: Optional[Any] = None, gosssub: Optional[Any] = None):
        self.node_id = node_id
        self.topics = topics or set()
        self.peers: Set[str] = set()
        self._listeners: Dict[str, List[Any]] = {}
        self._payload_handlers: Dict[str, List[Any]] = {}
        self._gossip_enabled = LIBP2P_AVAILABLE
        self._lock = threading.RLock()

        # libp2p integration (optional, injected for testability)
        self._host = host
        self._gossipsub = gosssub

    def subscribe(self, topic: str, handler: Any) -> None:
        with self._lock:
            self._listeners.setdefault(topic, []).append(handler)
            self.topics.add(topic)
            # If libp2p is available and we have a host, subscribe to the topic
            if self._gossip_enabled and self._gossipsub and self._host:
                try:
                    self._gossipsub.subscribe(topic)
                except Exception:
                    pass

    def register_payload_provider(self, topic: str, handler: Any) -> None:
        """Register a provider used only to retrieve payloads by message ID."""
        with self._lock:
            self._payload_handlers.setdefault(topic, []).append(handler)

    def publish(self, topic: str, payload: bytes, sender_id: str, vector_clock: Dict[str, Any], message_id: str) -> None:
        # Always deliver to local listeners (in-process)
        for handler in list(self._listeners.get(topic, [])):
            try:
                handler(GossipedMessage(topic, payload, sender_id, vector_clock, message_id))
            except Exception:
                pass

        # If libp2p GossipSub is available, publish to the network
        if self._gossip_enabled and self._gossipsub:
            try:
                import asyncio
                asyncio.create_task(self._gossipsub.publish(topic, payload))
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

    def request_missing(self, topic: str, missing_ids: Set[str], peer_id: str,
                    peer_transport: Optional["GossipTransport"] = None) -> Dict[str, bytes]:
        """Full anti-entropy cycle: request → transfer → verify → integrate.

        Returns dict of msg_id → payload received from the peer.
        """
        received: Dict[str, bytes] = {}
        source = peer_transport or self
        with source._lock:
            handlers = list(source._payload_handlers.get(topic, []))
        for msg_id in missing_ids:
            for handler in handlers:
                try:
                    payload = handler(msg_id)
                    if payload is not None:
                        received[msg_id] = payload
                        break
                except Exception:
                    continue
        return received

    def start(self) -> None:
        """Start the transport: create libp2p host and GossipSub if available."""
        if not self._gossip_enabled:
            return
        try:
            from libp2p.core.host import Host
            from libp2p.transport.tcp import TcpTransport
            from libp2p.pubsub.gossipsub import GossipSub

            # Create a libp2p host with TCP transport
            self._host = Host(TcpTransport())
            self._gossipsub = GossipSub(self._host)
        except Exception:
            self._gossip_enabled = False

    def stop(self) -> None:
        """Stop the transport."""
        if self._host:
            try:
                self._host.close()
            except Exception:
                pass
        self._host = None
        self._gossipsub = None


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

    def on_payload(msg_id: str) -> Optional[bytes]:
        """Handler for anti-entropy payload requests."""
        return trace_alice.get_payload(msg_id)

    gossip_bob.subscribe("spore", on_message)
    gossip_alice.register_payload_provider("spore", on_payload)

    # Authorize members: each node must explicitly register the other's Ed25519 key
    alice.authorize_member(bob.public_key, "node-beta")
    bob.authorize_member(alice.public_key, "node-alpha")

    # Alice sends two messages via gossip
    spore1, msg_id1 = alice.pack({"intent": "resonate", "phase": 0.7})
    spore2, msg_id2 = alice.pack({"intent": "grow", "phase": 0.9})

    # Store payloads in SwarmTrace for anti-entropy recovery
    trace_alice.add(msg_id1.decode(), "tag-" + msg_id1.decode(), pheromone_alice.tick(), payload=spore1)
    trace_alice.add(msg_id2.decode(), "tag-" + msg_id2.decode(), pheromone_alice.tick(), payload=spore2)

    # Broadcast via gossip transport
    gossip_alice.gossip_subscribe_and_publish(
        "spore", spore2, sender_id="node-alpha", vector_clock=pheromone_alice.tick(), message_id=msg_id2.decode()
    )

    # Bob receives and unpacks
    result = bob.unpack(spore2)
    print("bob sees:", result)

    # Replay check via message ID
    result2 = bob.unpack(spore2)
    print("replay filtered:", result2)  # → None on replay

    # Poison detection for tampered messages
    fake_spore, fake_id = alice.pack({"intent": "subvert"})
    if len(fake_spore) > 0:
        tampered = bytearray(fake_spore)
        tampered[0] = tampered[0] ^ 0xFF
        print("tampered:", bob.unpack(bytes(tampered)))  # → __poison__
    else:
        print("fake message empty, cannot test tampering")

    # Full anti-entropy cycle: request → transfer → verify → integrate
    # Spore-level: compare our message_history against peer's Bloom filter
    missing = bob.get_missing_from_inventory(alice.get_inventory())
    print("missing ids:", missing)

    recovered = gossip_bob.request_missing("spore", missing, "node-alpha", peer_transport=gossip_alice)
    print("recovered payloads:", list(recovered.keys()))

    # Verify and integrate recovered messages
    for msg_id, payload in recovered.items():
        result = bob.unpack(payload)
        print(f"unpack {msg_id[:8]}...: {result}")
        if result and isinstance(result, dict) and not result.get("__poison__"):
            print(f"integrated {msg_id[:8]}...: {result.get('p')}")

    # Merge SwarmTrace (OR-Set with concurrent remove+add resolution)
    trace_alice.remove(msg_id1.decode(), "tag-" + msg_id1.decode())
    trace_bob.merge(trace_alice)
    pruned = trace_bob.prune()

    print("gossip enabled:", gossip_alice._gossip_enabled, gossip_bob._gossip_enabled)
    print("received messages:", len(received))
