# Spore-Protocol

**Spore Protocol** is a versioned, self-contained messaging protocol designed for establishing causal ordering, ensuring message integrity, and providing replay detection in distributed, asynchronous systems. It combines several advanced cryptographic and data structure concepts—including Bloom Filters, Vector Clocks, and HMAC signing—to manage the complexity of a distributed message passing environment.

This protocol views data packages as "Spores"—packets that carry not just a payload, but also metadata necessary for ordering and verifying the message's place in a shared causal history.

---

## 💡 High-Level Overview

Spore solves the fundamental problem of communication in distributed environments: how do two or more nodes know if a received message is an update, a duplicate, a necessary continuation, or a poisoned message?

The Spore protocol achieves this by wrapping a volatile payload (`payload`) with:
1.  **Causal Metadata:** A `VectorClock` to track the causal history of the sender and merge states with the receiver.
2.  **Integrity Check:** An HMAC signature to prove authenticity and detect tampering.
3.  **Deduplication:** A Bloom Filter to efficiently detect and drop previously seen message formats (the compressed blobs).

### Key Features:

*   ✅ **Causal Ordering:** Vector Clocks allow recipients to determine if a message is causally dependent on their current state, or if it is a concurrent update.
*   ✅ **Tamper Detection:** All packets are signed, ensuring integrity during transit.
*   ✅ **Replay/Deduplication:** Bloom Filters enable immediate rejection of known message structures, crucial for efficiency.
*   ✅ **Asynchronous Friendly:** Designed to handle message delivery outside of strict sequence.

## ⚙️ Core Components (The Anatomy of a Spore)

The `Spore` class is the primary interface for using the protocol. It handles packing payloads into a transmittable blob and unpacking blobs back into meaningful data.

### 1. Bloom Filter (Replay Prevention)
*   **Function:** Provides a probabilistic check to determine if the *compressed* message body has been seen before.
*   **Operation:** Uses the SHA256 hash of the compressed raw data. If the filter returns `True`, the message has been seen (and is usually dropped as a duplicate).
*   **Note:** Like all Bloom Filters, it can produce false positives (reject a valid message) but has no false negatives (it never accepts a poison message it has seen).

### 2. Vector Clock (Causal Ordering)
*   **Function:** Tracks the history of updates. It consists of a map where each node ID holds an integer counter.
*   **`tick()` (Sender Side):** Increments the sender's counter, creating a new, unique causal history for the message.
*   **`merge()` (Receiver Side):** When a message arrives, the receiver merges the incoming Vector Clock into its local clock, determining if the incoming message is:
    *   **Causally follows:** The receiver can incorporate the message.
    *   **Concurrent:** The message is independent of the receiver's current state.
    *   **Happened before:** The receiver has already seen this message.

### 3. Host Secret & HMAC (Integrity)
*   **Function:** Secures the payload using a shared `secret` key (the `host_id` is used for the protocol instance, the `secret` is the encryption key).
*   **`_sign()`:** Creates a message tag over the JSON-serialized body, ensuring that the payload has not been modified and was genuinely created by the host.

---

## 🚀 Workflow Diagram

The process involves two primary directions: **Packing** (Sender) and **Unpacking** (Receiver).

### 📦 `Spore.pack(payload)` 📦

1.  **Payload Encapsulation:** The application payload is wrapped with the current causal metadata (`VectorClock.tick()`), a timestamp, and the `host_id`.
2.  **Serialization:** The body is JSON serialized and UTF-8 encoded.
3.  **Signing:** The serialized body is HMAC-signed.
4.  **Compaction:** The body + signature are compressed using `zlib`.
5.  **Bloom Update:** The compressed data hash is added to the Bloom Filter.
6.  **Output:** Returns the compressed binary blob.

### 📦 `Spore.unpack(raw)` 📦

1.  **Bloom Check:** The incoming raw data is checked against the Bloom Filter. If seen, it may be immediately discarded.
2.  **Decompression:** The data is decompressed.
3.  **Deserialization:** The blob is deserialized, revealing the message body and signature.
4.  **Verification:** The body bytes are verified against the signature. **If this fails, the message is poisoned/untrusted.**
5.  **Causal Merge:** The Vector Clock is merged into the recipient's clock, updating the causal state.
6.  **Application:** The application payload is returned upon successful decompression, deserialization, and verification.

---

## 🌐 Transport Layer (`tls_jitter` / `poison_on_tamper`)

The protocol includes optional wrapper functions to simulate real-world unreliable transport concerns:

*   **`wrap_as_tls_jitter()` / `unwrap_tls_jitter()`:** Adds a simple header (likely simulating the TLS record type header) for transport identification.
*   **`poison_on_tamper()`:** Adds a transaction tag (an additional message-level HMAC) for endpoints needing assurance that the message itself hasn't been tampered with at the transport level.

---

### ➡️ Usage Example (The Code Speaks)

```python
# Initialize the two ends with a shared secret
alice = Spore(host_id="node-alpha", secret=os.urandom(32))
bob = Spore(host_id="node-beta", secret=alice.secret) # Shared secret

# Alice packs a message
spore = alice.pack({"intent": "resonate", "phase": 0.7})
packet = wrap_as_tls_jitter(spore)

# Bob receives and unpacks the message
inner = unwrap_tls_jitter(packet)
result = bob.unpack(inner)
print("bob sees:", result)
```
