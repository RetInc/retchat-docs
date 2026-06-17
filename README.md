# Retchat Protocol Specification

> AI-generated docs on the RetChat Protocol

## Overview

Retchat is a TCP-based chat protocol with end-to-end encryption established via Diffie-Hellman key exchange. All messages after the handshake are encrypted with a per-message keystream derived from HMAC-SHA256 and authenticated with HMAC-SHA256.

---

## Transport

All communication runs over a plain TCP connection. The default port is **6677**. There is no TLS layer — security is handled entirely by the application-level encryption described below.

---

## Encryption

### Key Exchange

On connection, the server and client perform a Diffie-Hellman key exchange using the **RFC 3526 2048-bit MODP Group (Group 14)**:

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

The handshake sequence is:

1. Server generates a 256-bit private key and computes its public key.
2. Server sends its public key as: `[uint32 length (big-endian)] [bytes]`
3. Client receives the server's public key.
4. Client generates a 256-bit private key and computes its public key.
5. Client sends its public key as: `[uint32 length (big-endian)] [bytes]`
6. Both sides compute the shared secret and derive the base encryption key.

### Key Derivation

The 32-byte base encryption key is derived by computing SHA-256 over the raw bytes of the DH shared secret (with any leading zero byte stripped, matching OpenSSL's `BN_bn2bin` output).

### Per-Message Encryption

Each message uses a unique keystream derived from the base key and a monotonically increasing counter:

```
keystream = HMAC-SHA256(base_key, counter_bytes)
```

Where `counter_bytes` is the 64-bit counter encoded in **little-endian**. If more than 32 bytes are needed, the keystream is extended by chaining: `HMAC-SHA256(base_key, previous_digest)`.

The plaintext is XOR'd with the keystream. Send and receive counters are independent — each side maintains its own send counter and its own receive counter.

### Message Authentication

Every encrypted frame is authenticated with HMAC-SHA256 computed over the **ciphertext** (not plaintext), using the base encryption key. The HMAC is sent before the message length and ciphertext.

---

## Frame Format

After the handshake, all messages use this wire format:

```
+------------------+-------------------+------------------+
| HMAC-SHA256 (32) | Length (uint16 BE)| Ciphertext       |
+------------------+-------------------+------------------+
```

- **HMAC** (32 bytes): HMAC-SHA256 of the ciphertext, used to verify integrity before decryption. Frames with invalid HMACs are silently discarded.
- **Length** (2 bytes, big-endian): byte length of the ciphertext. Maximum is 4096 bytes.
- **Ciphertext**: the encrypted payload. After decryption, the first byte is the packet type, followed by the packet-specific payload.

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
| `0x01` | `HANDSHAKE`       | —         | Reserved for DH exchange (raw TCP) |
| `0x02` | `KEEPALIVE`       | c→s       | Ping                               |
| `0x03` | `KEEPALIVE_ACK`   | s→c       | Pong                               |
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
| `0x30` | `DISCONNECT`      | s→c       | Clean server-initiated disconnect  |
| `0x31` | `KICK`            | s→c       | Kicked by an admin                 |
| `0x32` | `BAN`             | s→c       | Banned by an admin                 |

---

## String Encoding

All strings are **null-terminated UTF-8**. When serialized into a packet payload, a string is written as its UTF-8 bytes followed by a `0x00` terminator byte.

---

## Packet Payloads

### `0x02` KEEPALIVE / `0x03` KEEPALIVE_ACK
No payload. The server sends a `KEEPALIVE` after 30 seconds of client inactivity; the client must reply with `KEEPALIVE_ACK` within 10 seconds or be disconnected. The client may also send `KEEPALIVE` proactively; the server replies with `KEEPALIVE_ACK`.

---

### `0x10` NICK_REQUEST (c→s)

| Field    | Type   | Description       |
|----------|--------|-------------------|
| newNick  | string | Requested nickname |

Nick rules enforced by the server: 1–20 characters, only `[A-Za-z0-9_-]`, must not be already taken in the current room, must not be banned.

---

### `0x11` NICK_ACK (s→c)

| Field   | Type   | Description              |
|---------|--------|--------------------------|
| newNick | string | The confirmed new nickname |

---

### `0x12` NICK_NOTIFY (s→c)

Broadcast to all other clients in the room when a user changes their nick.

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

Broadcast to all other clients in the room when a user joins.

| Field | Type   | Description          |
|-------|--------|----------------------|
| nick  | string | Nick of the new user |

---

### `0x16` LEAVE_NOTIFY (s→c)

Broadcast to all clients in the room when a user leaves or disconnects.

| Field | Type   | Description              |
|-------|--------|--------------------------|
| nick  | string | Nick of the departing user |

---

### `0x17` ROOM_LIST (s→c)

Variable number of null-terminated strings, one per room, concatenated directly.

| Field  | Type            | Description        |
|--------|-----------------|--------------------|
| rooms  | string[]        | List of room names |

---

### `0x18` USER_LIST (s→c)

Variable number of null-terminated strings, one per user in the current room.

| Field | Type     | Description       |
|-------|----------|-------------------|
| users | string[] | List of nicknames |

---

### `0x20` CHAT_MSG (c→s and s→c)

Client sends only `text`; the server fills in `sender` when broadcasting to the room.

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
| params     | string[] | `paramCount` null-terminated strings          |

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

---

### `0x22` DM_REQUEST (c→s)

| Field      | Type   | Description                |
|------------|--------|----------------------------|
| targetNick | string | Nick of the recipient      |
| text       | string | Message content            |

The server looks up `targetNick` across all connected clients (regardless of room). If not found, it responds with `SYSTEM_MSG` code `MSG_DM_TARGET_NOT_FOUND`. DMs are not stored.

---

### `0x23` DM_MSG (s→c)

| Field      | Type   | Description           |
|------------|--------|-----------------------|
| senderNick | string | Nick of the sender    |
| text       | string | Message content       |

---

### `0x30` DISCONNECT
No payload. Sent by the server before a clean shutdown.

---

### `0x31` KICK (s→c)

| Field  | Type   | Description        |
|--------|--------|--------------------|
| reason | string | Human-readable reason |

The client should close the connection after receiving this.

---

### `0x32` BAN (s→c)

| Field  | Type   | Description        |
|--------|--------|--------------------|
| reason | string | Human-readable reason |

The client should close the connection after receiving this. Reconnection will be refused at the TCP level if the IP is banned, or at the nick-change level if the nickname is banned.

---

## Connection Lifecycle

```
Client                              Server
  |                                    |
  |<---------- TCP connect ----------->|
  |                                    |
  |<-- [uint32 len] [server pub key] --|   DH handshake (plaintext)
  |-- [uint32 len] [client pub key] -->|
  |                                    |   Both derive base key via SHA-256(shared_secret)
  |                                    |
  |<===== all frames encrypted =======>|
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
  |-- CHAT_MSG ------------------------|   send a message
  |<-- CHAT_MSG (from others) ---------|   receive messages
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