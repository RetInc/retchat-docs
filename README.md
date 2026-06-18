# Retchat Protocol Specification

> Updated to reflect the current implementation as of 18th June 2026.  
> (Still AI-generated)

---

## Overview

Retchat is a TCP‑based chat protocol with application‑level encryption established via Diffie‑Hellman key exchange. After the DH key exchange, both sides exchange protocol version handshake packets to ensure compatibility. All subsequent messages are encrypted and authenticated using HMAC‑SHA256. The protocol is designed for real‑time messaging, supporting rooms, direct messages, and image sharing.

---

## Transport

All communication runs over a plain TCP connection. The default port is **6677**. There is no TLS layer — security is handled entirely by the application‑level encryption described below.

---

## Encryption & Handshake

### Diffie‑Hellman Key Exchange

On connection, the server and client perform a Diffie‑Hellman key exchange using the **RFC 3526 2048‑bit MODP Group (Group 14)**:

```
Prime (hex):
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
29024E088A67CC74020BBEA63B139B22514A08798E3404DD
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D
C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F
83655D23DCA3AD961C62F356208552BB9ED529077096966D
670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9
DE2BCBF6955817183995497CEA956AE515D2261898FA0510
15728E5A8AACAA68FFFFFFFFFFFFFFFF

Generator: 2
```

The handshake sequence:

1. Server generates a 256‑bit private key and computes its public key.
2. Server sends its public key as:  
   `[uint32 length (big‑endian)] [bytes]`
3. Client receives the server’s public key.
4. Client generates a 256‑bit private key and computes its public key.
5. Client sends its public key as:  
   `[uint32 length (big‑endian)] [bytes]`
6. Both sides compute the shared secret using the standard DH formula.

### Key Derivation

The 32‑byte base encryption key is derived by computing **SHA‑256** over the raw bytes of the DH shared secret, **with all leading zero bytes stripped** (matching OpenSSL’s `BN_bn2bin` behaviour).  
This ensures both sides derive an identical key even when the shared secret has different leading‑zero representations.

### Protocol Version Handshake

Immediately after the DH exchange, the **server** sends a `HANDSHAKE` packet (type `0x01`) containing its protocol version (16‑bit, big‑endian). The client must verify this version; if it matches, the client replies with its own `HANDSHAKE` packet containing its protocol version. If versions differ, the server may send a `SYSTEM_MSG` with code `12` (`MSG_VERSION_MISMATCH`) and then close the connection.

The `HANDSHAKE` packet is **encrypted** using the derived key (like all subsequent frames). The payload is exactly two bytes (the version number).

### Per‑Message Encryption

Each message uses a unique keystream derived from the base key and a monotonically increasing **per‑direction counter**:

```
keystream = HMAC‑SHA256(base_key, counter_bytes)
```

where `counter_bytes` is the 64‑bit counter encoded in **little‑endian**. If more than 32 bytes are needed, the keystream is extended by chaining:  
`HMAC‑SHA256(base_key, previous_digest)`.

The plaintext is XOR’d with the keystream.  
- **Send counter** increments after each transmitted frame.
- **Receive counter** increments after each successfully decrypted frame.

### Message Authentication

Every encrypted frame is authenticated with **HMAC‑SHA256** computed over the **ciphertext** (not plaintext), using the same base encryption key. The HMAC is sent before the length and ciphertext.  
If a received HMAC does not match the expected value, the connection is **immediately closed** (the implementation does not silently discard invalid frames).

---

## Frame Format

After the DH handshake, all messages use this wire format:

```
+------------------+---------------------+------------------+
| HMAC (32 bytes)  | Length (uint32 BE)  | Ciphertext       |
+------------------+---------------------+------------------+
```

- **HMAC** (32 bytes): HMAC‑SHA256 of the ciphertext.
- **Length** (4 bytes, big‑endian): byte length of the ciphertext. Maximum allowed is **2 MB** (2,097,152 bytes).
- **Ciphertext**: the encrypted payload. After decryption, the first byte is the packet type, followed by the packet‑specific payload.

Decrypted frame layout:

```
+------------+--------------------+
| Type (1)   | Payload (variable) |
+------------+--------------------+
```

---

## Packet Types

| Value  | Name              | Direction | Description                        |
|--------|-------------------|-----------|------------------------------------|
| `0x01` | `HANDSHAKE`       | both      | Protocol version exchange          |
| `0x02` | `KEEPALIVE`       | both      | Ping                               |
| `0x03` | `KEEPALIVE_ACK`   | both      | Pong                               |
| `0x10` | `NICK_REQUEST`    | c→s       | Request a nickname change          |
| `0x11` | `NICK_ACK`        | s→c       | Nickname change confirmed          |
| `0x12` | `NICK_NOTIFY`     | s→c       | Another user changed their nick    |
| `0x13` | `JOIN_REQUEST`    | c→s       | Request to join a room             |
| `0x14` | `JOIN_ACK`        | s→c       | Room join confirmed                |
| `0x15` | `JOIN_NOTIFY`     | s→c       | Another user joined the room       |
| `0x16` | `LEAVE_NOTIFY`    | s→c       | A user left the room               |
| `0x17` | `ROOM_LIST`       | s→c       | List of available rooms            |
| `0x18` | `USER_LIST`       | s→c       | List of users in the current room  |
| `0x20` | `CHAT_MSG`        | both      | Chat message                       |
| `0x21` | `SYSTEM_MSG`      | s→c       | System notification or error       |
| `0x22` | `DM_REQUEST`      | c→s       | Send a direct message              |
| `0x23` | `DM_MSG`          | s→c       | Incoming direct message            |
| `0x24` | `IMAGE_MSG`       | both      | Image message (with metadata)      |
| `0x30` | `DISCONNECT`      | s→c       | Clean server‑initiated disconnect  |
| `0x31` | `KICK`            | s→c       | Kicked by an admin                 |
| `0x32` | `BAN`             | s→c       | Banned by an admin                 |

---

## String Encoding

All strings are **null‑terminated UTF‑8**. When serialized into a packet payload, a string is written as its UTF‑8 bytes followed by a `0x00` terminator byte.

---

## Packet Payloads

### `0x01` HANDSHAKE (both)

Payload: exactly 2 bytes – the protocol version as a **big‑endian 16‑bit unsigned integer**.

- **Server** sends this first after DH exchange.
- **Client** verifies the version; if matching, it replies with its own `HANDSHAKE`.
- If versions differ, the server may send a `SYSTEM_MSG` (code 12) and then close the connection.

### `0x02` KEEPALIVE / `0x03` KEEPALIVE_ACK
No payload.  
- The server sends a `KEEPALIVE` after 30 seconds of client inactivity; the client must reply with `KEEPALIVE_ACK` within 10 seconds or be disconnected.  
- Clients may also send `KEEPALIVE` proactively; the server replies with `KEEPALIVE_ACK`.

---

### `0x10` NICK_REQUEST (c→s)

| Field    | Type   | Description       |
|----------|--------|-------------------|
| newNick  | string | Requested nickname |

Nickname rules (enforced by server):
- Length: 1 – 20 characters.
- Allowed characters: `[A-Za-z0-9_-]`.
- Must not be already taken in the current room.
- Must not be banned.

---

### `0x11` NICK_ACK (s→c)

| Field   | Type   | Description              |
|---------|--------|--------------------------|
| newNick | string | The confirmed new nickname |

---

### `0x12` NICK_NOTIFY (s→c)

Broadcast to all other clients in the room.

| Field   | Type   | Description     |
|---------|--------|-----------------|
| oldNick | string | Previous nickname |
| newNick | string | New nickname     |

---

### `0x13` JOIN_REQUEST (c→s)

| Field    | Type   | Description         |
|----------|--------|---------------------|
| roomName | string | Room to join        |

Rooms are created on demand. The client is silently moved from their current room; the server sends `LEAVE_NOTIFY` to the old room and `JOIN_NOTIFY` to the new room.

---

### `0x14` JOIN_ACK (s→c)

| Field    | Type   | Description        |
|----------|--------|--------------------|
| roomName | string | Room that was joined |

---

### `0x15` JOIN_NOTIFY (s→c)

Broadcast to all other clients in the room.

| Field | Type   | Description          |
|-------|--------|----------------------|
| nick  | string | Nick of the new user |

---

### `0x16` LEAVE_NOTIFY (s→c)

Broadcast to all clients in the room.

| Field | Type   | Description              |
|-------|--------|--------------------------|
| nick  | string | Nick of the departing user |

---

### `0x17` ROOM_LIST (s→c)

Variable number of null‑terminated strings, one per room, concatenated directly.

| Field  | Type            | Description        |
|--------|-----------------|--------------------|
| rooms  | string[]        | List of room names |

---

### `0x18` USER_LIST (s→c)

Variable number of null‑terminated strings, one per user in the current room.

| Field | Type     | Description       |
|-------|----------|-------------------|
| users | string[] | List of nicknames |

---

### `0x20` CHAT_MSG (both)

**Client → Server:**  
| Field  | Type   | Description          |
|--------|--------|----------------------|
| text   | string | Message content      |

The server fills in `sender` before broadcasting to the room.

**Server → Client:**  
| Field  | Type   | Description          |
|--------|--------|----------------------|
| sender | string | Nick of the sender   |
| text   | string | Message content      |

---

### `0x21` SYSTEM_MSG (s→c)

| Field      | Type     | Description                                  |
|------------|----------|----------------------------------------------|
| isError    | uint8    | `1` if this is an error, `0` if informational |
| code       | uint16 BE| Message code (see table below)                |
| paramCount | uint8    | Number of parameter strings that follow       |
| params     | string[] | `paramCount` null‑terminated strings          |

#### System Message Codes

| Code | Name                    | Params              | Description                                 |
|------|-------------------------|---------------------|---------------------------------------------|
| 1    | `MSG_WELCOME`           | nick, room          | Sent on connect with assigned nick and room |
| 2    | `MSG_NICK_EMPTY`        | —                   | Requested nick was empty                    |
| 3    | `MSG_NICK_TOO_LONG`     | maxLen              | Nick exceeds maximum length                 |
| 4    | `MSG_NICK_INVALID_CHARS`| —                   | Nick contains disallowed characters         |
| 5    | `MSG_NICK_SAME`         | —                   | Requested nick is already your current nick |
| 6    | `MSG_NICK_BANNED`       | —                   | Nick is banned                              |
| 7    | `MSG_NICK_TAKEN`        | nick                | Nick is already in use in this room         |
| 8    | `MSG_JOIN_ALREADY`      | —                   | Already in the requested room               |
| 9    | `MSG_JOIN_NAME_TAKEN`   | room                | Your nick is taken in the target room       |
| 10   | `MSG_DM_TARGET_NOT_FOUND` | nick              | DM target user is not connected             |
| 11   | `MSG_IMAGE_UNSUPPORTED` | mimeType            | Unsupported image MIME type                 |
| **12**| **`MSG_VERSION_MISMATCH`** | clientVersion, serverVersion | Protocol versions differ                   |

---

### `0x22` DM_REQUEST (c→s)

| Field      | Type   | Description                |
|------------|--------|----------------------------|
| targetNick | string | Nick of the recipient      |
| text       | string | Message content            |

The server looks up `targetNick` across all connected clients (regardless of room). If not found, it responds with `SYSTEM_MSG` code 10 (`MSG_DM_TARGET_NOT_FOUND`). DMs are not stored.

---

### `0x23` DM_MSG (s→c)

| Field      | Type   | Description           |
|------------|--------|-----------------------|
| senderNick | string | Nick of the sender    |
| text       | string | Message content       |

---

### `0x24` IMAGE_MSG (both)

**Client → Server:**  
| Field    | Type     | Description                    |
|----------|----------|--------------------------------|
| sender   | string   | (Reserved, must be empty)      |
| target   | string   | Empty for room broadcast, or recipient nickname for DM |
| mimeType | string   | MIME type (e.g. `image/png`)  |
| fileName | string   | Original file name (may be empty) |
| imageData| bytes    | Raw image data (max 2 MB after compression) |

The server overwrites `sender` with the client’s current nickname and validates `mimeType` against a whitelist (`image/png`, `image/jpeg`, `image/webp`, `image/avif`). If unsupported, it replies with `SYSTEM_MSG` code 11.

**Server → Client:**  
| Field    | Type     | Description                    |
|----------|----------|--------------------------------|
| sender   | string   | Nick of the sender             |
| target   | string   | Empty for room, or DM target   |
| mimeType | string   | MIME type                      |
| fileName | string   | Original file name             |
| imageData| bytes    | Raw image data                 |

The server broadcasts to the room if `target` is empty, or sends a direct message to the specified recipient.

---

### `0x30` DISCONNECT
No payload. Sent by the server before a clean shutdown.

---

### `0x31` KICK (s→c)

| Field  | Type   | Description        |
|--------|--------|--------------------|
| reason | string | Human‑readable reason |

The client should close the connection after receiving this.

---

### `0x32` BAN (s→c)

| Field  | Type   | Description        |
|--------|--------|--------------------|
| reason | string | Human‑readable reason |

The client should close the connection after receiving this. Reconnection will be refused at the TCP level if the IP is banned, or at the nick‑change level if the nickname is banned.

---

## Connection Lifecycle

```
Client                              Server
  |                                    |
  |<---------- TCP connect ----------->|
  |                                    |
  |<-- [uint32 len] [server pub key] --|   DH handshake (plaintext)
  |-- [uint32 len] [client pub key] -->|
  |                                    |   Both derive base key
  |                                    |
  |<===== frames now encrypted =======>|
  |                                    |
  |<-- HANDSHAKE (version) ------------|   Server sends protocol version
  |-- HANDSHAKE (version) ------------>|   Client replies if version matches
  |                                    |   (else SYSTEM_MSG(12) + close)
  |                                    |
  |<-- SYSTEM_MSG (MSG_WELCOME) -------|   nick="usuarioN", room="lobby"
  |<-- JOIN_NOTIFY --------------------|   broadcast to lobby
  |                                    |
  |-- NICK_REQUEST ------------------->|   optional: set preferred nick
  |<-- NICK_ACK -----------------------|
  |<-- NICK_NOTIFY (to room) ----------|
  |                                    |
  |-- JOIN_REQUEST ------------------->|   optional: join a room
  |<-- JOIN_ACK -----------------------|
  |<-- LEAVE_NOTIFY (old room) --------|
  |<-- JOIN_NOTIFY (new room) ---------|
  |                                    |
  |-- CHAT_MSG / IMAGE_MSG ------------|   send a message
  |<-- CHAT_MSG / IMAGE_MSG -----------|   receive messages
  |                                    |
  |     ... (keepalive every 30s) ...  |
  |                                    |
  |<-- DISCONNECT / KICK / BAN --------|   server terminates connection
  |                                    |
  |<---------- TCP close ------------->|
```

---

## Keepalive

The server tracks the time of the last received frame per client. After **30 seconds** of inactivity, it sends a `KEEPALIVE` packet. The client must respond with `KEEPALIVE_ACK` within **10 seconds**, or the server closes the connection. Clients may also send `KEEPALIVE` proactively; the server will respond with `KEEPALIVE_ACK`.

---

## Default Nick Assignment

On connect, before the client sends a `NICK_REQUEST`, the server assigns a temporary nickname of the form `usuarioN` where `N` is the socket file descriptor number.