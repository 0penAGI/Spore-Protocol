# Spore-Protocol

**Spore Protocol v0.5** — a self-contained messaging protocol with causal ordering, authenticated message bodies, stable message IDs, and bounded parsing.

Packages ("spores") carry not only a payload, but metadata to determine the message's place in a shared causal history.

---

## 💡 High-Level Overview

Spore solves the fundamental problem of communication in distributed environments: how do two or more nodes know if a received message is an update, a duplicate, a necessary continuation, or a poisoned message?

The Spore protocol achieves this by wrapping a volatile payload (`payload`) with:

1. **Causal Metadata:** A `VectorClock` to track the causal history of the sender and merge states with the receiver.
2. **Dual authentication:**
   - HMAC-SHA256 (shared group secret) — group membership verification.
   - Ed25519 (per-node key) — sender identity authentication, non-repudiation.
3. **Deduplication and anti-entropy:** Exact message history rejects repeats; Bloom is a probabilistic synchronization hint.
4. **Transport encryption:** ChaCha20Poly1305 (AEAD).

---

## ⚙️ Core Components (The Anatomy of a Spore)

The `Spore` class is the primary interface for using the protocol. It handles packing payloads into a transmittable blob and unpacking blobs back into meaningful data.

### 1. Bloom Filter (Anti-Entropy Hint)

*   **Function:** Provides a probabilistic hint for anti-entropy gossip; exact replay prevention uses message history.
*   **Operation:** Stores the raw 32-byte `blake2b(canonical_signed_body)` digest. Compression and envelope encoding do not affect a v0.5 ID.
*   **`merge(peer_bloom)`**: Union of two Bloom filters for anti-entropy synchronization.
*   **`get_missing_ids(peer_bloom)`**: Returns local IDs the peer's Bloom probably lacks (local minus peer); false positives can hide a missing ID.
*   **Exact inventory:** `get_inventory()` lists local IDs; `get_missing_from_inventory(peer_inventory)` returns peer IDs absent locally (peer minus local), without Bloom false positives.
*   **Note:** Like all Bloom Filters, it can produce false positives but no false negatives.

### 2. Vector Clock (Causal Ordering)

*   **Function:** Tracks the history of updates. It consists of a map where each node ID holds an integer counter.
*   **`tick()` (Sender Side):** Increments the sender's unbounded Python integer counter, creating a new causal history for the message.
*   **`merge()` (Receiver Side):** Merges incoming counters component-wise. Legacy `e` epoch fields are ignored.
*   **Bound:** Incoming clocks are limited to 4,096 node entries; local clocks remain unbounded integers.
*   **`happens_before(other)`:** Returns True if this event causally precedes `other` (self → other).
*   **`is_concurrent_with(other)`:** Returns True if events are concurrent (neither happens-before the other).

### 3. Dual Signatures (Integrity + Identity)

*   **HMAC-SHA256 (group_secret):** Proves group membership — any member can verify the message came from within the swarm.
*   **Ed25519 (private_key):** Proves specific node identity — sender cannot repudiate the message.
*   The public key is placed in the blob envelope (`blob["node_pubkey"]`), **not** inside the signed body.

### 4. Transport Encryption (ChaCha20Poly1305)

*   `encrypt_spore(spore_bytes, key)` → `nonce || ciphertext`
*   `decrypt_spore(sealed, key)` → `bytes | None` (verifies AAD = `b"spore-v0.4-enriched"`)

---

## 🚀 Workflow

### 📦 `Spore.pack(payload) -> (compressed_bytes, message_id)`

1. **Payload encapsulation:** Adds protocol version, fresh 128-bit nonce, causal metadata, timestamp, and `host_id`.
2. **Canonical body:** JSON uses sorted keys, compact separators, UTF-8, and rejects non-finite numbers.
3. **Stable ID:** `blake2b(body_bytes, digest_size=32)`; the ID is based on the exact body bytes that are signed.
4. **Signing:** Body is HMAC-signed with group secret and Ed25519-signed with node private key.
5. **Envelope and compression:** `{b: base64(body), g: hmac_sig, n: ed25519_sig, node_pubkey: pub}`, then zlib level 6.
6. **History:** Bloom receives raw digest bytes; the exact history retains the hex form for JSON/API compatibility.
7. **Output:** Returns `(compressed_blob, 64-character hex message_id as bytes)`.

### 📦 `Spore.unpack(raw, expected_msg_id=None) -> dict | None | {"__poison__": ...}`

1. Enforces compressed and decompressed size limits (defaults: 1 MiB and 4 MiB).
2. Parses and validates envelope/body types, strict base64, protocol version, nonce, and clock bounds.
3. Verifies HMAC, Ed25519 identity, and local membership authorization.
4. If `expected_msg_id` is supplied, compares it to the verified body ID before integration.
5. Rejects exact replays; records the digest and merges the vector clock only after verification.
6. Returns the verified body, `None` for malformed/replayed input, or a structured `__poison__` marker for failed authentication/ID checks.

v0.4 messages without a protocol version remain readable using their legacy compressed-envelope ID. v0.5 IDs are stable across recompression; v0.4 IDs are not.

---

## 🔒 Transport Layer

| Function | Description |
|----------|-------------|
| `encrypt_spore(bytes, key)` | ChaCha20Poly1305 with 12-byte nonce, AAD = `b"spore-v0.4-enriched"` |
| `decrypt_spore(bytes, key)` | Decrypt + verify AEAD tag |
| `poison_on_tamper(bytes, key)` | Transport-level HMAC tag (optional proof of tampering) |

`wrap_as_tls_jitter` / `unwrap_tls_jitter` **removed** — simulated TLS replaced with real AEAD encryption.

---

## 💡 Usage Example

```python
import os
from main import Spore, Ed25519KeyPair, encrypt_spore, decrypt_spore

# Shared group secret (HMAC) — same for all swarm members
group_secret = os.urandom(32)

# Each node generates its own Ed25519 keypair
alice_priv, alice_pub = Ed25519KeyPair.generate()
bob_priv, bob_pub = Ed25519KeyPair.generate()

alice = Spore(host_id="node-alpha", group_secret=group_secret,
              private_key=alice_priv, public_key=alice_pub)
bob = Spore(host_id="node-beta", group_secret=group_secret,
            private_key=bob_priv, public_key=bob_pub)

# Alice packs a message
spore, msg_id = alice.pack({"intent": "resonate", "phase": 0.7})

# (Optional) encrypt for transport
transport_key = os.urandom(32)  # shared encryption key
encrypted = encrypt_spore(spore, transport_key)

# ... transmit over network ...

# Bob decrypts and unpacks
decrypted = decrypt_spore(encrypted, transport_key)
result = bob.unpack(decrypted)
print("bob sees:", result)

# Replay is filtered
assert bob.unpack(decrypted) is None
```

---

## 🔄 Anti-Entropy (Gossip)

```python
# Exchange exact inventories to avoid Bloom false positives
missing = bob.get_missing_from_inventory(alice.get_inventory())

# Register payload retrieval separately from normal message delivery
gossip_alice.register_payload_provider("spore", trace_alice.get_payload)
recovered = gossip_bob.request_missing(
    "spore", missing, "node-alpha", peer_transport=gossip_alice
)
for msg_id, payload in recovered.items():
    result = bob.unpack(payload, expected_msg_id=msg_id)  # verifies ID before integrating
```

---

## 📋 API Summary

| Class / Function | Purpose |
|------------------|---------|
| `VectorClock` | Causal clocks with `happens_before` / `is_concurrent_with` |
| `BloomFilter` | Probabilistic filter with `merge` / `get_missing_ids` |
| `Ed25519KeyPair` | Ed25519 generation/signing/verification (PyNaCl) |
| `Spore` | Main interface: `pack`, `unpack`, exact inventory, Bloom compatibility methods |
| `SwarmTrace` | TTL-backed OR-Set trace and payload store |
| `GossipTransport` | Message delivery plus separate payload-provider registration |
| `encrypt_spore` / `decrypt_spore` | AEAD encryption for transport |
| `poison_on_tamper` | Transport HMAC tag (optional) |

---

## 🏷️ Versions

*   **v0.5** (current): Nonce-bound stable body IDs, bounded parsing, verified recovery IDs, Vector Clock ordering, Ed25519 identity, Bloom anti-entropy, ChaCha20Poly1305 encryption, HMAC group membership.
*   **v0.4** (legacy-readable): Shared HMAC + Ed25519, causal metadata, compressed-envelope IDs.
*   v0.3 (original): Shared HMAC only, no causal ordering, no Ed25519, with tls_jitter simulation.

---

## 🧪 Tests

```bash
python3 test_protocol.py
```

Tests: Vector Clock ordering, node identity, Bloom filter anti-entropy, replay protection, tamper detection.
