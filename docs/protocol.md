# The qsh/1 protocol

Status: draft, protocol version 1. Section numbers, message type numbers, error codes and
constants in this document are stable; text may still be clarified.

qsh is a remote shell that runs over QUIC, with TLS over TCP and an ssh pipe as fallbacks.
A session lives on the server and survives any number of broken connections; a client that
comes back gets every byte of output it missed. Trust is anchored in SSH: the client obtains
session credentials and the server's certificate fingerprint by running `qsh-server bootstrap`
over the user's own ssh, and every later connection is authenticated with those.

This document specifies everything needed to write an implementation that interoperates with
`qsh` and `qsh-server`: the bootstrap over ssh (section 10), the three transports (section 9),
the stream multiplexing layer used over byte-stream transports (section 8), the message format
(section 3), connection setup (section 5), session authentication (section 6) and the terminal
channel with its resume algorithm (section 7). The threat model is in
[security.md](security.md); the reasons behind the design are in Appendix B.

Contents

1. Overview
2. Conventions
3. Messages
4. Streams and channels
5. The control stream
6. Session authentication
7. The terminal channel
8. Stream multiplexing over byte streams
9. Transports
10. Bootstrap over ssh
11. Errors
12. Connection management
13. Extensibility and versioning
14. Registries
15. Security considerations
- Appendix A. Worked example and test vectors
- Appendix B. Design rationale
- Appendix C. Constants

## 1. Overview

```
client                                        server (one daemon per user)
  │  ssh host 'qsh-server bootstrap'             │
  │  stdin: request JSON ───────────────────────▶│ creates a session (pty + shell)
  │◀─────────────── stdout: one JSON line ───────│ session id, session key, ports,
  │                                              │ certificate SHA-256, versions
  │                                              │
  │  QUIC (or TLS/TCP, or `ssh host qsh-server pipe`), ALPN qsh/1, pinned certificate
  │  stream 0: CLIENT_HELLO ────────────────────▶│
  │  stream 4: ATTACH (session id, proof) ──────▶│ proof = HMAC(key, TLS exporter)
  │◀──────────────────────────── SERVER_HELLO ───│
  │◀──────────────── ATTACHED (next key, input received)
  │◀──────────────── OUTPUT (offset, bytes) ...  │
  │  INPUT (offset, bytes) ... ─────────────────▶│
  │  ACK ◀──────────────────────────────────────▶│
  │                                              │
  ×  connection lost: the session keeps running, output goes to a replay buffer
  │                                              │
  │  new connection, ATTACH with the rotated key and the output offset received so far
  │◀──── ATTACHED, then everything the client missed, then live output
```

A **session** is a pseudo-terminal running a login shell or a command on the server (or, for a
*pipe session*, a command connected by pipes, section 7.14). It is
identified by a 128-bit session id and authenticated by a 256-bit session key, both issued by
the bootstrap. Each direction of a session's terminal is a byte stream with 64-bit offsets;
the sender keeps unacknowledged bytes in a replay buffer, so a new connection resumes exactly
where the old one stopped.

A **connection** is a QUIC connection, a TLS connection or an ssh pipe between a client and
the per-user daemon. It carries one control stream and one stream per attached session. A
connection is a replaceable pipe: nothing is lost when it breaks.

## 2. Conventions

### 2.1 Requirements language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted
as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals,
as shown here.

### 2.2 Terminology

- **Client**: the endpoint that runs the bootstrap and opens connections (`qsh`, or a library
  user such as TokenSSH).
- **Server**: the per-user daemon (`qsh-server daemon`) that owns sessions, together with the
  helper commands `qsh-server bootstrap` and `qsh-server pipe` run over ssh.
- **Endpoint** / **peer**: either side of a connection / the other side.
- **Session**, **connection**: see section 1.
- **Stream**: a reliable, ordered, bidirectional byte stream within a connection: a QUIC
  stream, or a stream of the multiplexing layer (section 8).
- **Channel**: the use a stream is put to; the control stream, or a terminal channel.
- **Attachment**: the binding of a session to one terminal channel, from a successful ATTACH
  until that stream closes. A session has at most one attachment at a time.
- **Message**: the unit of the qsh/1 framing (section 3), carried on a stream.
- **Mux frame**: the unit of the multiplexing layer (section 8), never seen over QUIC.
- **Byte-stream transport**: TLS over TCP, or the ssh pipe.
- **Connection error**: an error that ends the whole connection (section 11).
- **Stream error**: an error that ends one stream; the connection and other streams continue.

### 2.3 Byte order and integer types

All multi-byte fixed-width integers are unsigned and in network byte order (big-endian), unless
a field says otherwise.

| Notation | Meaning |
|---|---|
| `u8`, `u16`, `u32`, `u64` | unsigned integer of 1, 2, 4, 8 bytes, big-endian |
| `varint` | variable-length integer, section 2.4 |
| `bytes[N]` | exactly N bytes |
| `string` | a `varint` length L, then L bytes of UTF-8 (no terminator) |
| `data…` | all remaining bytes of the payload |

Each `string` field states its maximum length L in bytes. A string longer than its maximum
is a FRAME_ERROR. Strings MUST be valid UTF-8; receivers MUST reject invalid UTF-8 in
capability names (FRAME_ERROR) and MAY replace invalid sequences in strings that are only
shown to people (error messages, implementation names).

Wire layouts are given in the notation of RFC 9000 section 1.3, for example:

```
PING Payload {
  Data (u64),
}
```

### 2.4 Variable-length integers

qsh uses the variable-length integer encoding of QUIC [RFC 9000, section 16]. The two most
significant bits of the first byte give the base-2 logarithm of the encoding's length in bytes;
the remaining bits, in network byte order, hold the value.

| 2MSB | Length | Usable bits | Range |
|---|---|---|---|
| 00 | 1 | 6 | 0 – 63 |
| 01 | 2 | 14 | 0 – 16 383 |
| 10 | 4 | 30 | 0 – 1 073 741 823 |
| 11 | 8 | 62 | 0 – 4 611 686 018 427 387 903 |

Examples: `25` decodes to 37; `7b bd` to 15 293; `9d 7f 3e 7d` to 494 878 333;
`c2 19 7c 5e ff 14 e8 8c` to 151 288 809 941 952 652; `40 25` also decodes to 37.

- Senders MUST use the shortest encoding for message types (section 3) and mux frame stream
  ids (section 8), and SHOULD use the shortest encoding everywhere else.
- Receivers MUST accept any valid encoding of every other varint field. A receiver MAY treat
  a message type that is not shortest-encoded as a FRAME_ERROR.
- A varint that is cut off by the end of its payload or frame is a FRAME_ERROR.

### 2.5 Cryptographic notation

- `HMAC-SHA256(K, M)`: HMAC [RFC 2104] with SHA-256 [FIPS 180-4], 32-byte output.
- `SHA-256(M)`: the SHA-256 digest of M.
- `||`: concatenation.
- `TLS-Exporter(label, context, length)`: the TLS 1.3 exporter [RFC 8446, section 7.5]; over
  QUIC, the exporter of the connection's TLS handshake [RFC 9001].
- Random values (session ids, keys, nonces) MUST come from a cryptographically secure random
  number generator.

## 3. Messages

### 3.1 Format

Every stream carries a sequence of messages:

```
Message {
  Type (varint),
  Length (varint),
  Payload (..),       // exactly Length bytes
}
```

`Length` is the length of `Payload` in bytes; it does not include the `Type` and `Length`
fields. Messages are not aligned and have no padding. A message may be split across transport
packets, QUIC STREAM frames or mux DATA frames at any byte boundary; receivers reassemble.

### 3.2 Size limits

Every stream and direction has a maximum payload length, which depends on the channel and on
the position of the message:

| Where | Maximum `Length` |
|---|---|
| Control stream, first message in each direction (CLIENT_HELLO; SERVER_HELLO or ERROR) | 2 048 (`MAX_HELLO`) |
| Control stream, any later message | 4 096 (`MAX_CONTROL`) |
| Channel stream, first message from the initiator (ATTACH) | 256 (`MAX_ATTACH`) |
| Terminal channel, any other message, either direction | 65 536 (`MAX_TERMINAL`) |

A receiver MUST check `Length` against the limit **before** it reads or allocates the payload,
and MUST treat a larger value as a MESSAGE_TOO_LARGE error (a connection error on the control
stream, a stream error on a channel stream). The limits apply to message types the receiver
does not know as well. Unauthenticated peers therefore cannot make the server allocate more
than a few kilobytes per connection (section 6.6 adds a total).

Senders SHOULD keep INPUT and OUTPUT messages at or below 16 384 bytes of data: smaller
messages interleave better with other channels and with control traffic.

### 3.3 Parsing payloads

- A payload shorter than the fields its type requires is a FRAME_ERROR.
- A payload longer than the fields the receiver knows for its type: the receiver MUST ignore
  the extra bytes. This lets a later revision append fields to a message; a sender MUST NOT
  append bytes unless a negotiated capability or the session kind (section 7.14) defines them.
  This rule does not apply to
  messages whose last field is `data…`, which by definition use the whole payload.
- Some layouts depend on the kind of the attached session: on a pipe session (section 7.14)
  ATTACH, ATTACHED, ACK sent by the client, and EXIT carry an appended field that is
  REQUIRED. For those messages "the fields its type requires" includes the appended field, so
  a pipe-session message without it is a FRAME_ERROR.
- Flag fields: senders MUST set undefined bits to zero; receivers MUST ignore undefined bits.
- Values that a field defines as invalid are a FRAME_ERROR unless the field says otherwise.

### 3.4 Unknown and unexpected messages

- **Unknown type on an established channel**: the control stream after the hello exchange, and
  a terminal channel after ATTACHED, are extensible. A receiver MUST skip a message whose type
  it does not know (reading and discarding `Length` bytes, subject to section 3.2) and continue.
  Consequently a sender MUST NOT send a type the peer might not know unless the peer has shown
  that it knows it, normally through a negotiated capability (section 5.4).
- **Unknown first message on a new stream**: the first message on a stream names the channel
  kind (section 4.3). If the receiver does not know it, it MUST end that stream with the stream
  error UNKNOWN_CHANNEL; the connection continues.
- **Unexpected message**: a known type on the wrong channel, in the wrong direction, or in the
  wrong state (for example INPUT before ATTACHED, or OUTPUT sent by a client) is a
  PROTOCOL_VIOLATION, a connection error on the control stream and a stream error elsewhere.
- **Before the hello exchange**: the first message on the control stream MUST be CLIENT_HELLO
  from the client, and SERVER_HELLO or ERROR from the server (ERROR when the server refuses
  the connection before any hello: UNSUPPORTED_VERSION, TIMEOUT, LIMIT_EXCEEDED, …); anything
  else, including an unknown type, is a PROTOCOL_VIOLATION connection error.
- **Before authentication** the server applies the stricter rules of section 6.6, which take
  precedence over this section: for example an unknown first message on a channel stream is
  then a PROTOCOL_VIOLATION connection error rather than UNKNOWN_CHANNEL.
- Type 0x00 is reserved and MUST NOT be sent; receivers treat it like any unknown type.

### 3.5 Message types

All message types of qsh/1. "C" is the client, "S" the server. The full registry, including
reserved ranges, is in section 14.1.

| Type | Name | Stream | Direction | Capability | Section |
|---|---|---|---|---|---|
| 0x00 | reserved | | | | 3.4 |
| 0x01 | CLIENT_HELLO | control | C→S | | 5.2 |
| 0x02 | SERVER_HELLO | control | S→C | | 5.3 |
| 0x03 | PING | control | both | | 5.5 |
| 0x04 | PONG | control | both | | 5.5 |
| 0x05 | PATH_INFO | control | S→C | | 5.6 |
| 0x06 | GOAWAY | control | both | | 5.7 |
| 0x07 | ERROR | any | both | | 5.8 |
| 0x10 | ATTACH | terminal (first) | C→S | | 7.2 |
| 0x11 | ATTACHED | terminal | S→C | | 7.3 |
| 0x12 | KEY_CONFIRM | terminal | C→S | | 6.5 |
| 0x13 | INPUT | terminal | C→S | | 7.4 |
| 0x14 | OUTPUT | terminal | S→C | | 7.4 |
| 0x15 | ACK | terminal | both | | 7.5 |
| 0x16 | OUTPUT_GAP | terminal | S→C | | 7.7 |
| 0x17 | RESIZE | terminal | C→S | | 7.9 |
| 0x18 | SNAPSHOT | terminal | S→C | `snapshot` | 7.8 |
| 0x19 | EXIT | terminal | S→C | | 7.10 |
| 0x1a | DETACH | terminal | C→S | | 7.11 |
| 0x1b | HANGUP | terminal | C→S | | 7.11 |
| 0x1c | OUTPUT_ZSTD | terminal | S→C | `zstd` | 7.12 |
| 0x1d | INPUT_EOF | terminal, pipe sessions | C→S | | 7.14.4 |
| 0x1e | ERROR_OUTPUT | terminal, pipe sessions | S→C | | 7.14.3 |
| 0x20–0x27 | reserved: port forwarding | | | `forward` | 14.1 |
| 0x28–0x2f | reserved: file copy | | | `copy` | 14.1 |
| 0x30–0x37 | reserved: agent forwarding | | | `agent` | 14.1 |

## 4. Streams and channels

### 4.1 Stream ids

Streams are bidirectional. Stream ids follow QUIC [RFC 9000, section 2.1] on every transport,
so the same id names the same stream in logs and code whatever the transport:

- Client-initiated streams have ids 0, 4, 8, … (low two bits `00`).
- Server-initiated streams have ids 1, 5, 9, … (low two bits `01`).
- Unidirectional streams (low bit 1 set, `x1x`) are not used in qsh/1. Over QUIC both
  endpoints advertise `initial_max_streams_uni = 0`; over the mux layer a frame for a
  unidirectional stream id is a PROTOCOL_VIOLATION.

### 4.2 The control stream

The control stream is stream 0. The client opens it first and sends CLIENT_HELLO on it before
any other message on the connection. There is exactly one control stream per connection
and it stays open for the connection's lifetime: if either direction of stream 0 is finished
or reset, the peer MUST treat it as a connection error (PROTOCOL_VIOLATION, or the code of the
reset). The control stream carries connection-wide messages: the hello exchange, PING/PONG,
PATH_INFO, GOAWAY and connection-level ERROR.

### 4.3 Channel streams

Every other stream carries exactly one channel. The initiator names the channel kind with the
first message it sends on the stream:

| First message | Channel | Opened by |
|---|---|---|
| ATTACH (0x10) | terminal channel (section 7) | client |
| reserved, `forward` / `copy` / `agent` | later revisions | either, after negotiation |

- qsh/1 defines only client-initiated channels. A server MUST NOT open a stream unless a
  negotiated capability defines a server-initiated channel. A client receiving a stream it did
  not expect MUST end it with UNKNOWN_CHANNEL: over the mux layer it sends RESET with
  UNKNOWN_CHANNEL for the stream (and credits the stream's data back to the connection window,
  section 8.3), so that the stream is closed for both endpoints and counts no longer against
  `MUX_MAX_STREAMS`; it MUST NOT silently ignore it. (Over QUIC the client's
  `initial_max_streams_bidi` of 0 makes such a stream a QUIC STREAM_LIMIT_ERROR.)
- Streams are independent: there is no ordering between messages on different streams. A
  client MAY open channel streams before it has received SERVER_HELLO (pipelining, section
  5.1), except over the ssh pipe, where ATTACH needs the server nonce (section 6.2).
- A server MUST NOT process the first message of a channel stream before it has accepted
  CLIENT_HELLO; it buffers that message (at most `MAX_ATTACH` bytes, section 3.2) until then.

### 4.4 Closing streams

- **Graceful**: each endpoint finishes its sending direction (QUIC: a STREAM frame with FIN;
  mux: FIN) after its last message. A stream is closed when both directions are finished.
- **Abort**: an endpoint that ends a stream because of an error first sends ERROR with the
  code on that stream if it can, then finishes its direction. When it cannot (the stream is
  blocked, or the error is in the framing itself), it resets the stream with the error code:
  over QUIC with RESET_STREAM and STOP_SENDING, over the mux layer with RESET.
- A stream that ends in the middle of a message is a FRAME_ERROR for that stream.

### 4.5 Limits

- At most `MAX_STREAMS` = 128 streams per initiator may be open at the same time, the control
  stream included. Over QUIC the server enforces this with `initial_max_streams_bidi` and
  MAX_STREAMS frames; over the mux layer it is a fixed limit (section 8.5).
- Before a connection is authenticated, stricter limits apply (section 6.6).

## 5. The control stream

### 5.1 The hello exchange

1. When the transport is established and the client decides to use the connection (section
   12.1), it opens stream 0 and sends CLIENT_HELLO. When the connection is not one of several
   candidates of a race (section 12.1), it MAY immediately open channel streams and send ATTACH
   on them (over QUIC and TLS), without waiting for SERVER_HELLO. Because streams are
   not ordered with respect to each other, ATTACHED or OUTPUT may then arrive before
   SERVER_HELLO; the client MUST buffer messages of channel streams (bounded by the stream flow
   control) until it has processed SERVER_HELLO, and MUST NOT treat their early arrival as an
   error.
2. The server reads CLIENT_HELLO (at most `MAX_HELLO` bytes), selects the version and the
   capabilities, and sends SERVER_HELLO. If no version is acceptable it sends ERROR
   (UNSUPPORTED_VERSION) and closes the connection.
3. The server then sends PATH_INFO (section 5.6).

The server MUST close a connection that has not delivered a complete CLIENT_HELLO within
`HELLO_TIMEOUT` = 10 s of the server accepting it (TIMEOUT); the time of the TLS handshake
counts (section 6.6).

### 5.2 CLIENT_HELLO (0x01)

```
CLIENT_HELLO Payload {
  Version Count (varint),               // 1 – 16
  Version (varint) ...,                 // Version Count entries, most preferred first
  Capability Count (varint),            // 0 – 32
  Capability (string, max 32) ...,      // Capability Count entries
  Implementation (string, max 64),      // e.g. "qsh-core/0.1.0", informative
}
```

A Version Count of 0 or above 16, or a Capability Count above 32, is a FRAME_ERROR.

### 5.3 SERVER_HELLO (0x02)

```
SERVER_HELLO Payload {
  Version (varint),                     // the selected protocol version
  Nonce (bytes[32]),                    // fresh random value for this connection
  Capability Count (varint),            // 0 – 32
  Capability (string, max 32) ...,      // the negotiated capabilities
  Implementation (string, max 64),
}
```

The server MUST generate a new random `Nonce` for every connection, on every transport. It is
used by the ssh pipe's channel binding (section 6.2); on QUIC and TLS it is unused.

### 5.4 Version and capability negotiation

**Versions.** This document defines version 1. The version is always fixed by the transport,
before any qsh message is exchanged, because the framing below the hello (the mux layer, the
hello layouts themselves) may differ between versions:

- Over QUIC and TLS it is chosen by ALPN (section 9): ALPN `qsh/1` means version 1.
- Over the ssh pipe it is chosen by the client on the command line of `qsh-server pipe`
  (`--version N`, section 10.5), from the versions listed in the bootstrap reply; the pipe
  preface confirms it.

CLIENT_HELLO lists all versions the client supports; the list MUST contain the transport's
version, and the server MUST select exactly that version in SERVER_HELLO. The list is a
cross-check that catches a confused transport layer; a server that finds the transport's version
missing from it sends ERROR (UNSUPPORTED_VERSION). The client MUST check that `Version` in
SERVER_HELLO equals the transport's version; otherwise PROTOCOL_VIOLATION.

**Capabilities** name optional features. The client lists all capabilities it supports. The
server answers with the negotiated set: the capabilities that it supports, that the client
listed, and that it enables on this connection. It MUST NOT list a capability the client did
not offer; a client receiving one MUST treat it as a PROTOCOL_VIOLATION. Both endpoints then
use exactly the negotiated set for the rest of the connection. Duplicate names in a list are
ignored; unknown names are ignored by the server (it simply does not return them).

Capability names are 1 to 32 bytes of lowercase ASCII letters, digits, `-` and `.`, starting
with a letter or digit. Names without a `.` are reserved for this specification (section
14.3). Names with a `.` are private, in reverse domain style (`org.example.feature`), and MUST
only be used by agreement between implementations; a private capability MAY enable message
types of the private range (section 14.1).

Capabilities defined by qsh/1:

| Capability | Meaning | Status |
|---|---|---|
| `zstd` | the server may send OUTPUT_ZSTD (section 7.12) | reserved, M2 |
| `snapshot` | the server may send SNAPSHOT to an attachment that asked for it (section 7.8) | reserved, M2 |
| `forward` | port forwarding channels | reserved, M3 |
| `copy` | file copy channels | reserved, M3 |
| `agent` | ssh agent forwarding | reserved, later |

Until the sections that define a reserved capability's semantics are complete, implementations
MUST NOT offer it.

### 5.5 PING (0x03) and PONG (0x04)

```
PING Payload {
  Data (u64),
}

PONG Payload {
  Data (u64),         // copied from the PING
}
```

Either endpoint MAY send PING once the connection is authenticated (section 6.6; for the client:
once it has received an ATTACHED on the connection). The receiver MUST answer with a PONG
carrying the same `Data`, without waiting for anything else. `Data` is opaque to the receiver;
a sender SHOULD put a monotonic timestamp in microseconds there, so that the round-trip time is
the current time minus `Data` of the PONG. A PONG that matches no outstanding PING is ignored.
An endpoint SHOULD NOT send more than one PING per second on average, and MAY ignore PINGs that
arrive faster than ten per second.

### 5.6 PATH_INFO (0x05)

```
PATH_INFO Payload {
  Sequence (varint),         // 0 for the first PATH_INFO of a connection, then +1 per change
  Family (u8),               // 0 unknown, 4 IPv4, 6 IPv6
  Address (bytes[0|4|16]),   // per Family
  Port (u16),                // 0 when unknown
}
```

The server tells the client the client's address and port as the server sees them. It sends
PATH_INFO right after SERVER_HELLO, and again every time the observed address of the
connection changes (QUIC connection migration or NAT rebinding). An IPv4-mapped IPv6 address
(`::ffff:a.b.c.d`) MUST be sent as Family 4. Over the ssh pipe the server MAY report the client
address of the ssh connection, if it knows it, and Family 0 otherwise. Any other Family value
is a FRAME_ERROR.

The client uses PATH_INFO to recognize the network it is on (path memory) and to detect NAT
timeouts: when the observed address or port changes although the client did not change its
own address, a NAT between them dropped the mapping and created a new one (section 12.4).

### 5.7 GOAWAY (0x06)

```
GOAWAY Payload {
  Error Code (varint),       // why, from section 11.2
  Message (string, max 256), // for people, may be empty
}
```

The sender will open no new streams on this connection, and will refuse new streams opened by
the peer after the peer received GOAWAY (with SHUTDOWN or IDLE as the stream error). Existing
channels continue; the sender closes the connection when they are done or when it has to.

- A server sends GOAWAY with SHUTDOWN when it stops (`qsh-server stop`, SIGTERM, system
  shutdown), after it has ended every session and delivered each attachment's final EXIT or
  ERROR (SESSION_ENDED) (section 7.13), and GOAWAY with IDLE before closing an idle connection
  (section 12.5).
- A client MAY send GOAWAY with NO_ERROR before it closes a connection on purpose.
- A client receiving GOAWAY with IDLE moves its sessions to a new connection when it needs to.
  A client receiving GOAWAY with SHUTDOWN follows section 7.13: if none of its sessions on that
  connection is left, it MUST NOT reconnect, and in particular MUST NOT start the ssh pipe
  transport, which would start a new daemon.

### 5.8 ERROR (0x07)

```
ERROR Payload {
  Error Code (varint),       // section 11.2
  Message (string, max 256), // for people, may be empty; MUST NOT contain secrets
}
```

ERROR may be sent on any stream, once, as the last message the sender sends on it:

- On the control stream it reports a connection error. The sender then closes the connection
  (section 11.1). The receiver MUST NOT send anything after receiving it except its own close.
- On a channel stream it reports a stream error. The sender finishes its direction of the
  stream after it; the receiver stops using the stream and finishes its own direction.

## 6. Session authentication

### 6.1 Session credentials

The bootstrap (section 10) creates each session with:

- a **session id**: 16 random bytes, unique on the server, not secret but not guessable either;
- a **session key**: 32 random bytes, secret, known only to the server and the client that ran
  the bootstrap (or the last client to which it was rotated, section 6.5).

The session key never appears in a message of this protocol except in ATTACHED, inside the
encrypted transport, when it is replaced. A connection proves knowledge of the key with a proof
bound to that connection.

### 6.2 Channel binding value

Each ATTACH proof is computed over a 32-byte channel binding value `CB`, which depends on the
transport:

- **QUIC and TLS over TCP**:

  ```
  CB = TLS-Exporter("EXPORTER-qsh-attach", Session ID, 32)
  ```

  The label is the 19 ASCII bytes `EXPORTER-qsh-attach`; the context value is the 16-byte
  session id. Both endpoints compute it from the connection's own TLS 1.3 handshake, so it is
  unique to the connection and to the session.

- **ssh pipe** (no TLS):

  ```
  CB = SHA-256("qsh/1 pipe attach" || Nonce || Session ID)
  ```

  where `"qsh/1 pipe attach"` is the 17 ASCII bytes without a terminator and `Nonce` is the
  32-byte value from this connection's SERVER_HELLO. Over the pipe the client MUST wait for
  SERVER_HELLO before sending ATTACH.

A server MUST compute `CB` according to the transport the connection actually arrived on, never
according to anything the client says.

### 6.3 Proof

```
Proof = HMAC-SHA256(Session Key, CB)
```

The client puts the 32-byte proof in ATTACH (section 7.2). The proof shows that the sender
knows the session key and is the TLS endpoint of this very connection: a proof observed or
relayed by anyone is useless on any other connection, and the key itself is never sent.

The server proves the same in the other direction, in ATTACHED (section 7.3):

```
Server Proof = HMAC-SHA256(Session Key, "qsh/1 attached" || CB)
```

where `Session Key` is the key that the client's proof matched and `"qsh/1 attached"` is the
14 ASCII bytes without a terminator. The client MUST verify it, in constant time, with the key
it used in ATTACH before it acts on anything else in ATTACHED; a mismatch is a connection error
(AUTH_FAILED), and the client MUST NOT store `Next Key`, send INPUT or trust the connection's
pin again without a new bootstrap. The certificate pin authenticates the daemon; the server
proof additionally shows that the peer knows this session's key, so that someone who stole only
the daemon's certificate key cannot pose as the session (see security.md, section 4.7).

### 6.4 Verification

When the server receives ATTACH (after it has accepted CLIENT_HELLO):

1. It looks up the session by `Session ID`. If there is none, the channel fails with
   SESSION_UNKNOWN.
2. It computes the expected proof with each currently valid key of the session (at most two,
   section 6.5) and compares each with the received proof in constant time. If none matches,
   the channel fails with AUTH_FAILED.
3. Otherwise the attach is authenticated; it continues with section 7.3.

On a failure the server SHOULD wait at least 500 ms before sending the ERROR; the delay holds
back only that stream, never the connection's other streams. Only AUTH_FAILED (a wrong proof)
counts as a **failed ATTACH**: SESSION_UNKNOWN is a normal outcome for a client that holds
several sessions (a hub) when one of them has ended, and does not count. While a connection
carries no attachment (no ATTACH on it has succeeded yet, or all its attachments have ended),
the server MUST close it after three failed ATTACHes on it (LIMIT_EXCEEDED); a connection that
carries an attachment is never closed for failed ATTACHes of other sessions, which just fail
their streams. The server also limits failures per source address (section 6.6).

A client receiving SESSION_UNKNOWN or AUTH_FAILED MUST NOT retry the same credentials on a new
connection; it bootstraps again over ssh (op `attach` for an existing session, section 10.3), or
tells the user the session is gone.

### 6.5 Key rotation

Every successful attach replaces the session key, so a key that leaked (from a backup, an old
state file, a log) stops working the next time the legitimate client connects.

The server keeps, per session, a **current** key and at most one **pending** key:

1. A proof is checked against the pending key (if any) and the current key.
2. If it matched the pending key, the pending key becomes the current key (the client got it
   last time even though its KEY_CONFIRM was lost).
3. The server generates a new random 32-byte key, stores it as the pending key, replacing any
   previous pending key, and sends it as `Next Key` in ATTACHED. At this point both the
   current key and the new pending key are valid.
4. When the client confirms the pending key with KEY_CONFIRM, the pending key becomes the
   current key and the previous current key is discarded. From then on only the new key is
   valid.

```
KEY_CONFIRM Payload {
  Key ID (bytes[8]),            // the first 8 bytes of SHA-256(Next Key)
}
```

`Key ID` names the key being confirmed: the first 8 bytes of the SHA-256 digest of the
`Next Key` of the ATTACHED that the client confirms. The payload is exactly 8 bytes at offset
0 (a shorter payload is a FRAME_ERROR). The ID is not secret (it travels inside the encrypted
transport and reveals nothing useful about a 256-bit key), but it makes the confirmation
unambiguous: a KEY_CONFIRM delayed behind a later attach can never promote a key it did not
see.

On receiving KEY_CONFIRM on the session's current attachment, the server computes the key ID
of its pending key and compares it with `Key ID` in constant time. If they are equal, it
promotes the pending key to current as in step 4. Otherwise (no pending key, a different
pending key, a repeated confirmation) it ignores the message; this is not an error. A
KEY_CONFIRM on a stream that is no longer the session's attachment is never processed (the
server stopped reading that stream, section 7.3).

The client, on receiving ATTACHED (and verifying its server proof), MUST first store `Next Key`
durably where its credentials live (replacing the old key; for `qsh`, the session's state file,
written atomically), then send KEY_CONFIRM with its key ID, and from then on use only `Next
Key`. If it cannot store the key durably, it MUST NOT send KEY_CONFIRM: it keeps the
attachment, keeps both keys in memory and uses `Next Key` for its next ATTACH; the old key stays
valid on the server, so a client restarted from its stored state can still attach.

A client that keeps credentials only in memory, by design (an embedder or a hub without a state
file, or `qsh` run with state files disabled), has no durable store to fall behind: its memory
*is* its store. It stores `Next Key` in memory, replacing the old key, and sends KEY_CONFIRM at
once. When such a client exits, the session can be reached again only through a bootstrap op
`attach` (section 10.3).

This rule guarantees that a connection lost at any moment never locks the client out: if
ATTACHED did not arrive, the old key is still valid; if it arrived but KEY_CONFIRM did not, the
new key is valid. The confidentiality of `Next Key` rests on the transport: TLS 1.3 on QUIC and
TCP, ssh on the pipe.

### 6.6 Unauthenticated connections

Anyone can reach the daemon's UDP and TCP ports. A connection is **pending** from the moment the
server accepts it, before any handshake: a TCP connection when `accept` returns it, a QUIC
connection when the server receives its first Initial packet and decides to process it (the
"incoming connection" of QUIC libraries, before the server commits any connection state). It
is **authenticated** from the moment the server accepts its first ATTACH (section 6.4) until it
closes; before that, including during the TLS handshake, it is **unauthenticated**. Every
limit below counts from acceptance, so a peer that opens connections and never finishes a
handshake is bounded exactly like one that finishes it and then idles.

For unauthenticated connections the server MUST enforce:

| Limit | Value | Action when exceeded |
|---|---|---|
| Complete CLIENT_HELLO received after the connection was accepted (this includes the TLS handshake) | 10 s (`HELLO_TIMEOUT`) | close, TIMEOUT |
| First ATTACH accepted after CLIENT_HELLO was received | 10 s (`AUTH_TIMEOUT`) | close, TIMEOUT |
| Stream bytes read before authentication: QUIC stream data on all streams; over the mux layer every byte of every frame | 16 384 (`MAX_PREAUTH_BYTES`) | close, LIMIT_EXCEEDED |
| Channel streams opened before authentication | 4 | close, LIMIT_EXCEEDED |
| Failed ATTACHes (AUTH_FAILED) per connection without an attachment (section 6.4) | 3 | close, LIMIT_EXCEEDED |
| Message sizes | `MAX_HELLO`, `MAX_ATTACH` (section 3.2) | MESSAGE_TOO_LARGE |
| Concurrent unauthenticated connections per daemon, counted from acceptance | 64 (`MAX_PREAUTH_CONNS`) | refuse new ones, below |
| Concurrent unauthenticated connections per source address (an IPv4 address; IPv6 addresses aggregated by /64 prefix; an IPv4-mapped IPv6 address counts as IPv4) | 8 (`MAX_PREAUTH_PER_SOURCE`) | refuse new ones, below |
| AUTH_FAILED per source address | token bucket, 10 per minute (burst 10) | refuse new connections from it until the bucket refills |

The values of the last three rows MAY be configurable; the others are fixed. **Refusing** a
connection costs the server nothing beyond the refusal: over QUIC it answers the Initial with
CONNECTION_CLOSE (CONNECTION_REFUSED) without creating connection state, over TCP it closes the
accepted socket at once, before any TLS. Over QUIC the server MUST send a Retry (validating the
client's address before it keeps any state, RFC 9000 section 8.1.2) for every new incoming
connection while more than half of `MAX_PREAUTH_CONNS` connections are unauthenticated, and
MAY always do so. The per-source counts use the validated address when a Retry was used.

**QUIC flow control before authentication.** A QUIC stack buffers stream data up to the flow
control limits it advertised, whether or not the application reads it. The server therefore
MUST advertise an `initial_max_data` (the connection-level window) of at most 65 536 bytes, MUST
NOT raise it with MAX_DATA before the connection is authenticated, and raises it afterwards
(section 9.1). Separately, it counts the stream bytes it reads before authentication: when they
exceed `MAX_PREAUTH_BYTES`, it stops reading and closes the connection with LIMIT_EXCEEDED. The
first rule bounds memory (64 KiB per connection, whatever the stream windows), the second
bounds the work an unauthenticated peer can make the server do. A correct client needs far less
than either: a CLIENT_HELLO and a few ATTACHes.

Before authentication the server MUST accept only CLIENT_HELLO on the control stream and only
ATTACH as the first message of channel streams; any other message, including an unknown one,
is a PROTOCOL_VIOLATION connection error. It answers nothing but SERVER_HELLO, PATH_INFO and
ERROR, so an unauthenticated peer gets no amplification and learns little: that a qsh server is
there, and, for a session id it already knows, whether that session exists (SESSION_UNKNOWN or
AUTH_FAILED). Session ids are 128-bit random values that never appear outside encrypted
channels, so the latter reveals nothing to anyone who does not already hold one.

**Process limits.** Each pending connection costs the daemon a file descriptor over TCP. A daemon
SHOULD raise its soft `RLIMIT_NOFILE` to the hard limit at start, so that the limits above,
and not the descriptor table, decide when connections are refused. Every request on the
daemon's local control socket (bootstrap, pipe, status, stop; section 10.4) MUST have a
deadline (for example 10 s to receive the complete request and 10 s to deliver the answer), so
that a stuck local client cannot hold a descriptor or a task forever. Once a `pipe` request has
been answered, the socket carries a qsh connection over the ssh pipe transport, which is subject
to this section like any other connection, except for the per-source rows (it has no network
source address).

### 6.7 What authentication does not cover

The client authenticates the server with the pinned certificate (section 9.4). The server does
not authenticate the client as a person or as a user account: it authenticates knowledge of a
session key. That key was given, over ssh, to someone who had logged in as the user. The
session's processes run as the daemon's user, which is that same user. See
[security.md](security.md).

## 7. The terminal channel

### 7.1 Model

A session is a pseudo-terminal whose child process is the user's login shell or a command
(section 10.3). (A *pipe session* has pipes instead of a pseudo-terminal and a third stream for
standard error; section 7.14 describes how it differs. Sections 7.1 to 7.13 describe tty
sessions and apply to pipe sessions except where section 7.14 says otherwise.) It has two byte
streams:

- **output**: everything the program writes to the terminal, server to client;
- **input**: everything the user types or pastes, client to server.

Each byte of each stream has an **offset**: the number of bytes of that stream before it, since
the session was created. Offsets are 64-bit and start at 0; they never wrap (an offset plus a
length that would exceed 2^64 − 1 is a FRAME_ERROR).

For each stream, the sender keeps a **replay buffer** holding the bytes from offset `base` to
`end` (exclusive), where `end` is the total number of bytes produced so far; the receiver keeps
`received`, the offset of the first byte it has not received. Acknowledgements (ACK) let the
sender advance `base`.

A terminal channel carries one attachment of one session. A connection may carry many terminal
channels, for different sessions; a session has at most one attachment at a time, and the
newest attach wins (section 7.3).

### 7.2 ATTACH (0x10)

The client opens a new stream and sends ATTACH as its first message:

```
ATTACH Payload {
  Session ID (bytes[16]),
  Proof (bytes[32]),            // section 6.3
  Output Received (u64),        // the client's `received` for output, or LATEST
  Columns (u16),
  Rows (u16),
  Width Pixels (u16),           // 0 when unknown
  Height Pixels (u16),          // 0 when unknown
  Flags (varint),
}
```

Flags:

| Bit | Name | Meaning |
|---|---|---|
| 0 (0x1) | ACCEPT_SNAPSHOT | the client accepts SNAPSHOT on this attachment; ignored unless `snapshot` was negotiated |
| 1 (0x2) | FRESH | the client has no stream state for this session (first attach after the bootstrap, or a new client process using stored or re-issued credentials) |

A client that has stream state (it has attached this session before, in this process or from a
state file that records offsets) sends its output `received` and does not set FRESH. A client
without stream state sets FRESH and chooses where output starts: `Output Received` = 0 replays
everything the server still buffers (the default; it restores the scrollback), and
`Output Received` = `LATEST` (2^64 − 1) starts at the current end, skipping the backlog. LATEST
without FRESH is a FRAME_ERROR. The terminal size has the same meaning as in RESIZE (section
7.9). On a pipe session ATTACH carries one more field, `Error Received` (section 7.14.2).

After ATTACH the client MUST NOT send anything on the stream until it has received ATTACHED (or
ERROR).

**One attach at a time.** An ATTACH is *outstanding* from the moment it is sent until ATTACHED or
ERROR arrives on its stream, or until the client abandons it by resetting the stream
(CANCELLED); after abandoning a stream the client ignores everything that still arrives on it. A
client MUST NOT have more than one outstanding ATTACH for the same session, across all its
connections: concurrent attaches would take the session from each other and rotate the key under
each other's feet. Once a client has sent an ATTACH for a session, it MUST ignore every message
that arrives on older streams of that session (OUTPUT, ATTACHED, ACK, …) and stop sending on
them; their late data could otherwise move its offsets past what the new stream sends.

### 7.3 ATTACHED (0x11)

```
ATTACHED Payload {
  Input Received (u64),         // the server's `received` for input
  Output Start (u64),           // offset at which output on this attachment starts
  Next Key (bytes[32]),         // section 6.5
  Server Proof (bytes[32]),     // section 6.3
}
```

On a pipe session ATTACHED carries one more field, `Error Start` (section 7.14.2).

The server processes an authenticated ATTACH as follows; the steps are atomic with respect to
other attaches of the same session (a pipe session applies them to both output streams, with
the differences of section 7.14.5):

1. It computes the start offset `S`: `Output Received`, or the output `end` if it is LATEST.
   If `S` is greater than `end`, the channel fails with SEQUENCE_ERROR (the key is not rotated).
2. If the session has an attachment on another stream (on this or another connection), that
   attachment ends: the server stops reading the old stream **before** it takes the input
   `received` value for step 3 (input not yet accepted from the old stream is dropped; the
   client resends it), sends ERROR (SESSION_TAKEN_OVER) on the old stream and finishes it. Only
   the newest attachment receives output.
3. It rotates the key (section 6.5) and sends ATTACHED with its input `received`,
   `Output Start` = `S`, the new key and the server proof.
4. It sets the terminal size from ATTACH (section 7.9).
5. It discards output below `S` from its replay buffer (`base` = max(`base`, `S`)).
6. It sends output starting at `S`, preceded by OUTPUT_GAP if `S` is below `base` (section 7.7),
   and EXIT once the program has exited and all output has been sent (section 7.10). When `S`
   was LATEST or a gap was sent, it SHOULD make the program redraw (section 7.7).

The client, on ATTACHED:

1. Verifies `Server Proof` (section 6.3).
2. Without FRESH: checks that `Output Start` equals the `Output Received` it sent, and that its
   input `base` ≤ `Input Received` ≤ its input `end`. Otherwise the session state is
   inconsistent: the client fails the channel with SEQUENCE_ERROR and treats the session as lost.
   With FRESH: it sets its input `base` and `end` to `Input Received` (input the user typed while
   attaching follows from there), and its output `received` to `Output Start`.
   In both cases the client MUST reject (SEQUENCE_ERROR, session lost) values it cannot use
   safely: an `Output Start` or `Input Received` of LATEST (2^64 − 1), and any value from which
   its offset arithmetic could overflow 2^64 − 1. Clients MUST do all offset arithmetic checked
   (an overflow is an error, never a wrap) and MUST NOT trust a server's offset as a buffer size.
3. Discards input below `Input Received` and resends the input from `Input Received` to `end`
   as INPUT messages, in order, each with at most 16 384 bytes of data.
4. Stores `Next Key` and sends KEY_CONFIRM with its key ID (section 6.5).
5. Continues with live input, RESIZE and ACK.

### 7.4 INPUT (0x13) and OUTPUT (0x14)

```
INPUT Payload {
  Offset (u64),                 // offset of the first byte of Data in the input stream
  Data (..),                    // data…, at least 1 byte
}

OUTPUT Payload {
  Offset (u64),                 // offset of the first byte of Data in the output stream
  Data (..),                    // data…, at least 1 byte
}
```

Within one attachment both streams are contiguous:

- The first INPUT after ATTACHED has `Offset` = `Input Received` of ATTACHED; every later INPUT
  starts where the previous one ended.
- The first OUTPUT, OUTPUT_GAP, SNAPSHOT or OUTPUT_ZSTD after ATTACHED starts at
  `Output Start` of ATTACHED; every later one starts where the previous one ended (for
  OUTPUT_GAP, at its `To`; for SNAPSHOT, at its `Offset`; for OUTPUT_ZSTD, after its
  decompressed content).

A receiver MUST treat any other offset, and empty `Data`, as a SEQUENCE_ERROR stream error.
Neither side may reorder, drop or duplicate bytes of an accepted message.

**Input is committed to the session, not to the connection.** The server *receives* input when
it accepts it into the session's input queue, which belongs to the session (it survives the
connection) and is written to the pseudo-terminal in order. The server MUST keep reading the
terminal stream while the queue has room (capacity at least 64 KiB, default 1 MiB), so that
messages behind INPUT (RESIZE, DETACH, HANGUP, KEY_CONFIRM, ACK) are processed promptly even when
the program is not reading its terminal; only when the queue is full does it stop reading the
stream and let flow control hold the client back. Input that arrives after the pseudo-terminal
was closed (the program ended) is accepted, acknowledged and discarded. The client writes OUTPUT
data to its terminal in order; output is received when it has been written.

### 7.5 ACK (0x15)

```
ACK Payload {
  Received (u64),               // first offset not yet received
}
```

The client acknowledges output, the server acknowledges input. `Received` is cumulative: every
byte before it has been received in the sense of section 7.4. (On a pipe session the client's
ACK has a second field, `Error Received`, for the error output stream; section 7.14.2.)

**Validity.** For each stream it sends, a data sender keeps, per attachment:

- `last_ack`: the highest `Received` it has accepted from the peer on this attachment. It
  starts at the attachment's start offset: `Output Start` of ATTACHED for output (the server),
  `Input Received` of ATTACHED for input (the client). It only ever moves when an ACK is
  accepted. In particular, sending OUTPUT_GAP or SNAPSHOT never moves `last_ack`: the bytes
  they skip were never sent, so they cannot have been acknowledged.
- `sent_end`: the offset just after the last byte it has sent or skipped on this attachment
  (an OUTPUT_GAP or SNAPSHOT moves `sent_end` to its `To` or `Offset`).

An ACK is valid if `last_ack` ≤ `Received` ≤ `sent_end`; the sender then sets `last_ack` =
`Received` and MAY discard bytes below `Received` from its replay buffer. A server SHOULD NOT
discard acknowledged output of a tty session before its replay capacity is reached: kept as
scrollback, it is what a FRESH attach from offset 0 (a new client process, section 7.2) shows,
instead of a blank screen. A pipe session's server discards acknowledged bytes, since its
buffers are also its flow control (section 7.14). An ACK with
`Received` > `sent_end` acknowledges bytes that were never sent: the receiver fails the channel
with SEQUENCE_ERROR. An ACK with `Received` < `last_ack` is stale and MUST be ignored; it is not
an error. (A correct peer never sends one: ACKs on a stream are not reordered and `Received`
never decreases. But a stale ACK does no harm, while failing the channel on it would end an
attachment over a difference in bookkeeping, for example in how a peer counts a GAP.)

The rule matters around OUTPUT_GAP: a client may send ACK with a `Received` below the gap's
`To` before the OUTPUT_GAP reaches it. That ACK is valid (it lies between `last_ack` and
`sent_end`) even though the bytes it covers have already left the replay buffer.

A sender of ACK MUST NOT acknowledge bytes it has not received. `Output Received` in ATTACH
(unless LATEST) and `Input Received` in ATTACHED act as acknowledgements too.

Cadence: a receiver SHOULD send ACK when 32 768 bytes or more are unacknowledged, or 200 ms after
the oldest unacknowledged byte arrived, whichever comes first, and MUST send it within 1 s of
receiving data. The server SHOULD acknowledge input within 200 ms. ACKs are not acknowledged.

### 7.6 Replay buffers and output pacing

**Server, output.** The server keeps output from `base` to `end` in its replay buffer, with a
capacity of at least 1 MiB (default 8 MiB). When new output would exceed the capacity, the
server discards the oldest bytes, advancing `base`, **even if they are unacknowledged**. The
server MUST keep reading the pseudo-terminal whether or not a client is attached or keeping up:
a slow or absent client never blocks the program.

The server SHOULD NOT keep more than about two bandwidth-delay products of output (at least
256 KiB) sent but unacknowledged on an attachment; the rest waits in the replay buffer. The
amount in flight is `sent_end − max(last_ack, gap_to)` (section 7.5), where `gap_to` is the `To`
of the latest OUTPUT_GAP (or the `Offset` of the latest SNAPSHOT) sent on the attachment, 0 if
none: skipped bytes are not in flight, and the server MUST NOT wait for an acknowledgement of
them before it sends more. This
keeps the transport's buffers short, so that output can still be skipped (section 7.8) and an
interrupt typed by the user is followed quickly by the program's reaction.

**Client, input.** The client keeps all unacknowledged input in its replay buffer, with a
capacity of at least 64 KiB (default 1 MiB). It MUST NOT discard unacknowledged input: dropping
keystrokes could change the meaning of what the user typed. When the buffer is full the client
stops reading local input until acknowledgements free space.

### 7.7 OUTPUT_GAP (0x16)

```
OUTPUT_GAP Payload {
  From (u64),
  To (u64),                     // From < To
}
```

When the server must send output starting at an offset below its `base` (the client was away
or slow and the bytes fell out of the replay buffer), it sends OUTPUT_GAP with `From` = the
offset it should have sent and `To` = `base`, and continues with OUTPUT at `base`. This can
happen at attach (step 6 of section 7.3) and during an attachment.

- OUTPUT_GAP is not an acknowledgement: the server's `last_ack` stays where the client's
  ACKs put it (section 7.5), and ACKs the client sent before it processed the gap remain valid.
- The client sets its output `received` to `To`. It SHOULD tell the user that `To − From`
  bytes of output were skipped (for example in its status line), and MAY reset terminal state
  that a cut-off escape sequence could have left behind.
- After sending OUTPUT_GAP the server SHOULD make the program redraw its screen, for example by
  changing the pseudo-terminal's window size and changing it back, which delivers SIGWINCH;
  full-screen programs repaint, a shell's prompt is unaffected.
- `From ≥ To`, or a `From` that is not the expected offset (section 7.4), is a SEQUENCE_ERROR.
- OUTPUT_GAP is also how the server announces output it will never send because the session is
  ending (section 7.11): it then carries `To` = the output end, and EXIT follows.
- OUTPUT_GAP is never sent on a pipe session (section 7.14.5).

### 7.8 SNAPSHOT (0x18) — capability `snapshot` (semantics: M2)

```
SNAPSHOT Payload {
  Offset (u64),                 // output offset the screen state corresponds to
  Flags (u8),                   // bit 0: FINAL
  Columns (u16),
  Rows (u16),
  Data (..),                    // data…, terminal bytes that redraw the screen
}
```

Smart catch-up: when the client is far behind (for example several seconds of a fast-scrolling
program's output over a slow link), the server may skip the backlog and send the current screen
instead. SNAPSHOT may be sent only if the `snapshot` capability was negotiated **and** the
ATTACH had the ACCEPT_SNAPSHOT flag.

Semantics fixed now:

- A snapshot replaces the output from the expected offset `S` (section 7.4) up to `Offset`:
  the client treats it as OUTPUT_GAP{S, Offset} followed by `Data`. `Offset` ≥ `S`.
- A snapshot may be split into several SNAPSHOT messages, sent back to back with no other
  output message in between, all with the same `Offset`, `Columns` and `Rows`; the last has
  FINAL set. The client applies them in order and sets `received` = `Offset` after the FINAL
  one. A snapshot's total `Data` MUST NOT exceed 1 MiB.
- `Data` does not consume output offsets; output continues at `Offset`.

Left to M2 (servers MUST NOT send SNAPSHOT and clients MUST NOT offer `snapshot` until then): the
exact content profile of `Data` (which terminal sequences it may use, how it restores modes,
the alternate screen and the cursor), and when a server chooses to send it.

### 7.9 RESIZE (0x17)

```
RESIZE Payload {
  Columns (u16),
  Rows (u16),
  Width Pixels (u16),           // 0 when unknown
  Height Pixels (u16),          // 0 when unknown
}
```

The client sends RESIZE when its terminal's size changes. The server sets the
pseudo-terminal's window size (`TIOCSWINSZ`), which delivers SIGWINCH to the foreground process
group. A size with 0 columns or 0 rows MUST be ignored. Servers MAY clamp very large sizes.
On a pipe session, which has no terminal, the server ignores RESIZE (section 7.14.5).

### 7.10 EXIT (0x19)

```
EXIT Payload {
  Output End (u64),             // total length of the output stream
  Kind (u8),                    // 0 exited, 1 killed by a signal
  Status (u32),                 // Kind 0: exit status (0–255); Kind 1: 0
  Flags (u8),                   // bit 0: CORE_DUMPED
  Signal (string, max 32),      // Kind 1: signal name without "SIG", e.g. "TERM"; Kind 0: empty
}
```

On a pipe session EXIT has an appended field, `Error End (u64)`, the total length of the error
output stream (section 7.14.2).

When the session's program has ended (the child process was reaped) and the server has read
the pseudo-terminal to its end (on a pipe session: both the stdout and the stderr pipe to end
of file), the server sends all remaining output and then EXIT. Signal names are those of RFC
4254, section 6.10 ("ABRT", "HUP", "INT", "KILL", "TERM", …), or the name without "SIG" of a
signal not listed there. Any other Kind is a FRAME_ERROR.

**EXIT comes after all output**: the server sends it only once every byte of output up to
`Output End` has been either sent or announced as skipped with OUTPUT_GAP (section 7.11 says
when the server may skip), and sends no output message after it. When the client processes EXIT, its output `received`
therefore equals `Output End` (and, on a pipe session, its error `received` equals `Error
End`); any other value is a SEQUENCE_ERROR.

After EXIT the server sends nothing on the channel except ACK and, finally, its FIN. The client
sends ACK with `Output End` (and `Error End`) and finishes the stream. The server MAY then
discard the session immediately; otherwise the session is kept for `EXITED_TTL` (section 7.13),
so a client that was away when the program ended can still attach and receive the last output
and the EXIT.

A command-line client exits with `Status` for Kind 0, and with 128 + N for Kind 1, where N is
the number of the named signal on the client's own system (so "TERM" gives 143 on Linux), as
shells report a child killed by a signal; for a signal name it does not know, it exits with
255.

### 7.11 DETACH (0x1a) and HANGUP (0x1b)

```
DETACH Payload {
}

HANGUP Payload {
}
```

- **DETACH** ends the attachment and keeps the session running (`~d`). The client sends DETACH
  after its last INPUT and finishes its direction. On receiving it, the server stops sending
  output at once (output it has not sent stays in the replay buffer for the next attach), sends
  a final ACK covering all input received before DETACH, and finishes its direction. The client
  SHOULD wait for the server's FIN (up to 2 s) before it exits, so that typed input is not lost.
  The client's output `received` is whatever it had received when the FIN arrived.
- **HANGUP** ends the session (`~.`). The server *hangs the session up*, below.
  HANGUP is queued behind INPUT on the stream; if the session's input queue is full (section
  7.4) it takes effect only when the program reads, and `qsh kill` over ssh is the way to end
  such a session at once.

**Hanging up a session** is what HANGUP, bootstrap op `kill`, `DETACHED_TTL` and daemon shutdown
(section 7.13) do. The session's program runs as the leader of its own process group and
session (`setsid`); on a tty session the pseudo-terminal is its controlling terminal. The
server:

1. sends SIGHUP to the session's process group **and** closes its side of the session's
   terminal: the pseudo-terminal's master (which is what hangs up the tty: the kernel sends
   SIGHUP to the terminal's session and further reads and writes fail), or, on a pipe session,
   the stdin, stdout and stderr pipes. Closing alone is not enough on every system, and the
   signal alone leaves a program that ignores SIGHUP holding the terminal; it does both, as an
   sshd does when a connection closes;
2. waits up to 2 s for the program to end, reaping it;
3. ends the attachment, if there is one, with exactly one final message: if the program ended
   in time, EXIT, preceded by the output that is still to be sent; otherwise ERROR
   (SESSION_ENDED). The server MAY truncate the remaining output (for example when the client
   is not reading); on a tty session it then sends OUTPUT_GAP up to the output end before EXIT,
   on a pipe session (which has no gaps, section 7.14.5) it sends ERROR (SESSION_ENDED) instead
   of EXIT. Output the program writes after step 1 is lost, as with ssh: the `Output End` of
   such an EXIT is the end of the output the server had read when it closed the terminal. It
   then finishes the stream;
4. removes the session at once, whether or not the program has ended: its id becomes unknown
   (later ATTACHes get SESSION_UNKNOWN), its key and replay buffers are erased, and no part of
   it is kept waiting for the program. A session never outlives its removal;
5. MAY, if the process group still exists 5 s after the SIGHUP, send it SIGKILL. Processes that
   left the group (a job an interactive shell put in its own process group, a program that
   called `setsid`) are not signalled, as with ssh. The server keeps reaping its children after the session is
   gone.

A terminal stream that ends without DETACH or HANGUP (finished, reset, or the connection lost)
ends the attachment the same way as DETACH: the session keeps running.

**How an attachment ends, seen from the client.** Every attachment the server ends ends with
exactly one of: EXIT (the program ended), ERROR with SESSION_ENDED (the session was ended
without an exit status to report, or its output was truncated: HANGUP timeout, `qsh kill`, TTL,
daemon shutdown), ERROR with SESSION_TAKEN_OVER, another ERROR, or the server's FIN after
DETACH. No output follows EXIT or the ERROR (section 7.10); after EXIT only ACKs may follow.

### 7.12 OUTPUT_ZSTD (0x1c) — capability `zstd` (reserved, M2)

```
OUTPUT_ZSTD Payload {
  Offset (u64),                 // offset of the first decompressed byte
  Frame (..),                   // data…, one complete zstd frame [RFC 8878]
}
```

Reserved for compressed output. The decompressed content is exactly what an OUTPUT with the
same `Offset` would carry. The zstd frame MUST declare its content size, which MUST be between 1
and 65 536 bytes; a receiver MUST check the declared size before decompressing and treat a
larger one, or a frame whose output does not match it, as a FRAME_ERROR. Frames are
independent (no shared context between messages), so replay and resume work unchanged.
Dictionaries and when to compress are left to M2; until then the capability MUST NOT be
offered.

### 7.13 Session lifetime

- A session exists from its bootstrap until it is removed. It does not depend on any
  connection.
- A session with no attachment for `DETACHED_TTL` = 6 hours is hung up by the server (section
  7.11; there is no attachment to notify).
- A session whose program has exited is removed `EXITED_TTL` = 1 hour after the exit, or
  earlier as described in section 7.10.
- HANGUP and `qsh kill` (bootstrap op `kill`) hang a session up and remove it at once; an
  attached client receives EXIT or ERROR (SESSION_ENDED) as in section 7.11.
- Sessions live in the daemon's memory: when the daemon stops, all its sessions end. On a
  request to stop (SIGTERM, `qsh-server stop`, a service manager stopping the unit) the daemon:
  1. stops accepting connections and bootstrap requests;
  2. hangs up every session (section 7.11, all at once, so the 2 s waits overlap);
  3. on every attachment, sends the final EXIT or ERROR (SESSION_ENDED) of section 7.11;
  4. then sends GOAWAY (SHUTDOWN) on every connection;
  5. then closes the connections (allowing about 1 s for the messages above to be delivered)
     and exits.
- A client that receives GOAWAY (SHUTDOWN) and has no session left on that connection (each
  ended with EXIT or SESSION_ENDED) MUST NOT reconnect to that server, and in particular MUST
  NOT open the ssh pipe transport, whose `qsh-server pipe` would start a new daemon. A client
  that still has sessions it did not see end MAY reconnect (with back-off); a daemon that was
  restarted answers SESSION_UNKNOWN.

Servers MAY make the TTLs configurable and MUST document their values.

### 7.14 Pipe sessions

#### 7.14.1 Model

A session is of one of two **kinds**, fixed when the bootstrap creates it (member `tty`, section
10.3) and reported in the bootstrap reply:

- a **tty session** (the default): the program runs on a pseudo-terminal, as described in
  sections 7.1 to 7.13;
- a **pipe session** (`"tty": false`): the program runs with three pipes as its standard input,
  output and error. There is no pseudo-terminal, no line discipline, no echo, no `\n` to
  `\r\n` translation and no controlling terminal: the bytes are delivered exactly, in both
  directions, as `ssh host command` without a pseudo-terminal delivers them. This is what
  scripts, `qsh host cmd < file`, `qsh host tar c dir > dir.tar` and programs that use qsh as a
  transport need.

A pipe session has three byte streams, each with its own offsets starting at 0, its own replay
buffer and its own acknowledgements:

| Stream | Direction | Carried by | Acknowledged by |
|---|---|---|---|
| input (the program's stdin) | C→S | INPUT, then INPUT_EOF | ACK from the server |
| output (stdout) | S→C | OUTPUT | ACK from the client, `Received` |
| error output (stderr) | S→C | ERROR_OUTPUT | ACK from the client, `Error Received` |

Everything in sections 7.1 to 7.13 applies to pipe sessions except as stated here. Both kinds use
the same terminal channel (the channel opened by ATTACH); the session kind decides which of the
layouts and messages below apply. A tty session's encodings are unaffected by this section.

#### 7.14.2 Layouts on a pipe session

On a pipe session four messages carry one appended, REQUIRED field (section 3.3). Offsets are
from the start of the payload.

```
ATTACH Payload (pipe session) {
  Session ID (bytes[16]),       // offset 0
  Proof (bytes[32]),            // offset 16
  Output Received (u64),        // offset 48, stdout; or LATEST
  Columns (u16),                // offset 56, ignored
  Rows (u16),                   // offset 58, ignored
  Width Pixels (u16),           // offset 60, ignored
  Height Pixels (u16),          // offset 62, ignored
  Flags (varint),               // offset 64, F bytes (F = 1 for the flags of qsh/1)
  Error Received (u64),         // offset 64 + F, stderr; or LATEST
}                               // 73 bytes when F = 1

ATTACHED Payload (pipe session) {
  Input Received (u64),         // offset 0
  Output Start (u64),           // offset 8, stdout
  Next Key (bytes[32]),         // offset 16
  Server Proof (bytes[32]),     // offset 48
  Error Start (u64),            // offset 80, stderr
}                               // 88 bytes

ACK Payload (pipe session, client to server) {
  Received (u64),               // offset 0, stdout
  Error Received (u64),         // offset 8, stderr
}                               // 16 bytes

EXIT Payload (pipe session) {
  Output End (u64),             // offset 0, total length of stdout
  Kind (u8),                    // offset 8
  Status (u32),                 // offset 9
  Flags (u8),                   // offset 13
  Signal (string, max 32),      // offset 14, a varint length L (V bytes) then L bytes
  Error End (u64),              // offset 14 + V + L (15 + L with the shortest varint)
}
```

The server's ACK (acknowledging input) has the single `Received` field on both kinds. The
server checks the two fields of the client's ACK separately, each against its own stream's
`last_ack` and `sent_end` (section 7.5): one field may be stale, and is then ignored, while the
other advances; either one above its `sent_end` is a SEQUENCE_ERROR. The cadence rules of
section 7.5 apply to each output stream; one ACK always carries both values.

A pipe-session message without its appended field is a FRAME_ERROR (an ATTACH without
`Error Received` fails the channel before the key is rotated). A server receiving an ATTACH
with the extra field for a tty session ignores it (section 3.3). A client that expected a pipe
session and receives an ATTACHED without `Error Start` has a wrong idea of the session's kind:
it fails the channel with SEQUENCE_ERROR and treats the session as lost.

`Error Received` in ATTACH follows the rules of `Output Received` (section 7.2): LATEST is
allowed only with FRESH.

#### 7.14.3 ERROR_OUTPUT (0x1e)

```
ERROR_OUTPUT Payload {
  Offset (u64),                 // offset of the first byte of Data in the error output stream
  Data (..),                    // data…, at least 1 byte
}
```

ERROR_OUTPUT carries what the program writes to its standard error, exactly as OUTPUT carries
its standard output (section 7.4), with its own offsets: the first ERROR_OUTPUT after ATTACHED
starts at `Error Start`, every later one where the previous one ended; any other offset, or
empty `Data`, is a SEQUENCE_ERROR. A client writes it to its own standard error. The ordering
between OUTPUT and ERROR_OUTPUT is the order in which the server read the two pipes; as with
ssh, it is not a promise about the order in which the program wrote them. ERROR_OUTPUT on a tty
session is a PROTOCOL_VIOLATION.

#### 7.14.4 INPUT_EOF (0x1d)

```
INPUT_EOF Payload {
  Offset (u64),                 // the input end: offset just after the last byte of input
}
```

INPUT_EOF closes the program's standard input after all input before `Offset` (the client's
input end of file: its local standard input reached end of file). `Offset` MUST equal the
offset at which the next INPUT would start (section 7.4); any other value is a SEQUENCE_ERROR.
After sending INPUT_EOF the client sends no more INPUT for the session, on any attachment.

- The server accepts INPUT_EOF into the session's input queue (section 7.4), behind the input
  before it; from then on the input stream is **closed at `Offset`** for the rest of the
  session, whatever happens to the connection. When the server has written all input before
  `Offset` to the stdin pipe, it closes the pipe, so the program reads end of file.
- On a later attachment, after resending its unacknowledged input (section 7.3), a client that
  has sent INPUT_EOF sends it again with the same `Offset`. INPUT_EOF does not consume an
  offset and is not acknowledged; repeating it is how it survives a lost connection. A server
  whose input stream is already closed at `Offset` ignores a repeated INPUT_EOF with that
  `Offset`; INPUT, or INPUT_EOF with another `Offset`, after the input stream was closed is a
  SEQUENCE_ERROR.
- If the program closes its standard input first, input that arrives later is accepted,
  acknowledged and discarded, as after a pseudo-terminal closed (section 7.4).
- INPUT_EOF on a tty session is a PROTOCOL_VIOLATION; a client signals end of input there as a
  terminal does, by sending the terminal's EOF character (normally `^D`) as INPUT.

#### 7.14.5 Replay buffers and flow: no gaps

A pipe session's output is data, not a screen, and must arrive exactly: a dropped byte would
corrupt a file or a protocol run over qsh. So the server never discards unacknowledged output
of a pipe session and never sends OUTPUT_GAP (or SNAPSHOT) for it. Instead it applies
**back-pressure**, like a pipe and like ssh:

- The server keeps each of the two output streams in its own replay buffer (stdout: at least
  1 MiB, default 8 MiB; stderr: at least 64 KiB, default 1 MiB). When a buffer is full of
  unacknowledged bytes, the server stops reading that pipe until ACKs free space; the program
  then blocks when it writes to it. The rule of section 7.6 that a slow client never blocks
  the program applies to tty sessions only.
- Output pacing (section 7.6) applies to each stream separately.
- `Columns`, `Rows` and pixel sizes in ATTACH are ignored, the server MUST ignore RESIZE, and a
  client SHOULD NOT send RESIZE on a pipe session.

Attach offsets: the server computes the start offsets `S` (stdout) and `E` (stderr) from
`Output Received` and `Error Received` as in step 1 of section 7.3, and fails the channel with
SEQUENCE_ERROR, before rotating the key, if either is above its stream's end. If a start offset
is below its stream's `base` (bytes that an earlier attachment acknowledged):

- with FRESH, the stream starts at `base` instead (`Output Start` = max(`S`, `base`), likewise
  `Error Start`): the new client process gets everything that has not been delivered yet;
- without FRESH, the client claims not to have bytes it (or a client sharing its state)
  acknowledged, which is impossible for a correct client: SEQUENCE_ERROR, before rotating the
  key.

#### 7.14.6 Resume

Resume works for each stream as in section 7.3: the client sends `Output Received` and
`Error Received` in ATTACH; the server answers with `Input Received`, `Output Start` and
`Error Start`, then sends the output from `Output Start` and the error output from `Error
Start`, interleaved as it likes; the client resends its input from `Input Received`, followed
by INPUT_EOF if it had sent one. Without FRESH, the client checks `Error Start` = `Error
Received` as it checks `Output Start` (section 7.3, client step 2). With FRESH it sets its error
`received` to `Error Start`.

#### 7.14.7 End

When the program has been reaped and both the stdout and the stderr pipe have reached end of
file (as with ssh, a background process that keeps either open delays the end), the server
sends the remaining output of both streams, then EXIT with `Output End` and `Error End`
(section 7.10). When a pipe session is hung up (section 7.11) and the server will not deliver
all remaining output, it ends the attachment with ERROR (SESSION_ENDED) instead of EXIT.

## 8. Stream multiplexing over byte streams

QUIC provides streams natively. TLS over TCP and the ssh pipe provide a single byte stream, so
qsh/1 defines a small multiplexing layer ("mux") on top of them that provides the same
streams: bidirectional, reliable, ordered, with the same ids (section 4.1), with independent
flow control, half-close and abort. Every channel therefore works on every transport. Over
QUIC this layer is absent and MUST NOT be used.

### 8.1 Frames

After the transport's preface (none for TLS, section 10.5 for the pipe), each direction of the
byte stream is a sequence of mux frames:

```
Mux Frame {
  Frame Type (u8),
  Type-Specific Fields (..),
}

DATA Frame {                       // Frame Type 0x00
  Stream ID (varint),
  Length (varint),                 // 1 – 16 384 (MUX_MAX_DATA)
  Data (..),                       // exactly Length bytes of the stream
}

FIN Frame {                        // Frame Type 0x01
  Stream ID (varint),              // the sender has finished sending on this stream
}

RESET Frame {                      // Frame Type 0x02
  Stream ID (varint),
  Error Code (varint),             // section 11.2
}

WINDOW Frame {                     // Frame Type 0x03
  Stream ID (varint),
  Increment (varint),              // additional bytes the peer may send on this stream
}

CONN_WINDOW Frame {                // Frame Type 0x04
  Increment (varint),              // additional bytes the peer may send on the connection
}
```

- A DATA frame with `Length` 0 or above `MUX_MAX_DATA`, or a frame type other than 0x00–0x04,
  is a connection error (FRAME_ERROR). The mux layer is not extensible: a change to it
  requires a new protocol version.
- Frames are not padded or aligned. A receiver MUST NOT allocate memory based on `Length`
  beyond `MUX_MAX_DATA`.

### 8.2 Stream lifecycle

- **Open.** A stream is opened by the first DATA frame its initiator sends with its id. Each
  initiator MUST use its ids in order: the first stream it opens has the lowest id of its kind
  (0 for the client, 1 for the server) and each next one has the previous id plus 4. The
  receiver MUST treat as a PROTOCOL_VIOLATION: a DATA frame with an unused id of the peer's
  kind other than the next one; any other frame for an id of the peer's kind that has not been
  opened yet; any frame for an id of the receiver's own kind that the receiver has not opened;
  any frame for a unidirectional id.
- **Half-close.** FIN says the sender will send no more DATA on the stream (QUIC: FIN). DATA
  after FIN on the same stream is a PROTOCOL_VIOLATION.
- **Abort.** RESET aborts both directions of the stream (QUIC: RESET_STREAM together with
  STOP_SENDING), with an error code. After sending RESET an endpoint ignores further frames for
  the stream; after receiving RESET it discards buffered data of the stream, sends no more frames
  for it, and does not answer with RESET.
- **Closed.** For each endpoint, a stream is closed as soon as it has both sent and received
  FIN for it, or has sent or received RESET for it. Closure depends only on frames, never on
  whether the application has read the data, so both endpoints agree on which streams are
  open (the byte stream is ordered: a FIN or RESET always arrives before any DATA its sender
  sends afterwards). Data received before the closing frame is still delivered to the
  application. Ids are never reused.
  Frames that arrive for a closed stream are ignored, except that their DATA still counts
  against the connection window and is credited back as discarded data (section 8.3).

### 8.3 Flow control

Flow control bounds the memory a receiver must commit, per stream and per connection. It is
credit based, in the style of QUIC.

- For every stream and direction, the sender has **stream credit**, initially
  `MUX_STREAM_WINDOW` = 262 144 bytes. For the whole connection and direction it has
  **connection credit**, initially `MUX_CONN_WINDOW` = 1 048 576 bytes. Both initial values
  are fixed by this specification; there is no negotiation.
- Only the `Length` of DATA frames counts. A sender MUST NOT send a DATA frame larger than its
  remaining stream credit or its remaining connection credit; each DATA frame reduces both by
  its `Length`. FIN and RESET are always allowed.
- A receiver that receives more data than the credit it has granted MUST treat it as a
  connection error (FLOW_CONTROL_ERROR).
- WINDOW adds `Increment` to the stream credit of the stream in the frame; CONN_WINDOW adds it
  to the connection credit. An `Increment` of 0 has no effect. If a credit would exceed
  2^62 − 1, the receiver of the frame MUST treat it as a FLOW_CONTROL_ERROR. WINDOW for a stream
  that is closed or reset is ignored.

Receiver rules, which together make the layer deadlock free and bounded in memory:

1. **Stream credit follows the application.** A receiver returns stream credit (WINDOW) as the
   channel consumes data from the stream's buffer. It SHOULD send WINDOW once the application has
   consumed half of the current window. It MUST NOT grant more stream credit than it is willing
   to buffer for that stream. A channel that stops reading stalls only its own stream.
2. **Connection credit follows the demultiplexer.** A receiver returns connection credit
   (CONN_WINDOW) as soon as it has moved DATA into the stream's buffer, or discarded it (closed
   or reset stream), independently of whether any channel reads it. It MUST NOT withhold
   connection credit because a stream's application is not reading. The connection window thus
   only bounds data in flight that has not been demultiplexed yet; it cannot be used up by one
   stalled stream and block the others (the deadlock HTTP/2 can run into).
3. Memory per connection is therefore bounded by `MUX_CONN_WINDOW` plus the sum of the stream
   windows the receiver has granted, at most `MUX_MAX_STREAMS` × the largest stream window.
4. **Never stop reading.** An endpoint MUST keep reading and processing incoming frames while
   its own writes are blocked (by the transport or by missing credit). Two endpoints that both
   wait for their writes to complete before reading again would deadlock on a single TCP
   connection or ssh pipe whatever the credit rules say. Incoming data that the application
   cannot take yet goes into the stream's buffer, which credit already bounds.

A receiver MAY grant credit beyond the initial values (window auto-tuning) to fill a path with a
large bandwidth-delay product.

### 8.4 Scheduling

Senders SHOULD send DATA of different streams round-robin, in frames of at most `MUX_MAX_DATA`
bytes, and SHOULD give the control stream (stream 0) priority, so that PING, PONG and GOAWAY
are not queued behind bulk output. Senders SHOULD send WINDOW and CONN_WINDOW frames ahead of
queued DATA.

### 8.5 Limits

- `MUX_MAX_STREAMS` = 128 open streams per initiator, the control stream included, counted
  with the frame-based closure of section 8.2. Opening a 129th is a connection error
  (STREAM_LIMIT).
- Before authentication the server applies section 6.6: in particular, it closes the connection
  when more than 4 channel streams are opened or more than `MAX_PREAUTH_BYTES` bytes of DATA
  arrive.

### 8.6 Closing the connection

An endpoint closes a mux connection after sending ERROR on the control stream (or GOAWAY and
the end of all streams) by closing the transport: over TLS with a `close_notify` alert followed
by closing the TCP connection, over the pipe by closing its end. An end of the byte stream that
was not preceded by ERROR or GOAWAY on the control stream (including one in the middle of a
frame) means the connection was lost; sessions are not affected (section 7.11).

## 9. Transports

A client may use any of three transports to reach the same daemon and the same sessions. It
races them (section 12.1); the first one to answer the hello wins.

| Transport | Underlay | Streams | Channel binding (section 6.2) | Version from |
|---|---|---|---|---|
| QUIC | UDP, server's `udp` port | QUIC streams | TLS exporter | ALPN `qsh/1` |
| TLS | TCP, server's `tcp` port | mux layer (section 8) | TLS exporter | ALPN `qsh/1` |
| ssh pipe | `ssh host … qsh-server pipe` | mux layer (section 8) | server nonce | `pipe --version N` |

### 9.1 QUIC

QUIC version 1 [RFC 9000] secured with TLS 1.3 [RFC 9001], loss recovery and congestion control
per [RFC 9002] or any congestion controller that is safe for the Internet.

- **ALPN**: the client MUST offer `qsh/1` (the 5 ASCII bytes) and the server MUST select it or
  fail the handshake with the `no_application_protocol` alert. A client that offers no ALPN
  extension at all MUST be refused the same way (some TLS libraries accept such clients by
  default; a qsh server must not). After the handshake, both endpoints MUST check that the
  negotiated protocol is exactly `qsh/1` (or another version this endpoint supports, section
  13.1) and close the connection otherwise, before sending any qsh message. A client that
  supports later versions offers their ALPN ids too.
- **Certificate**: verified by pinning, section 9.4. Clients connect by address, SHOULD NOT send
  the Server Name Indication extension, and servers MUST NOT require it.
- **Streams**: qsh streams are QUIC bidirectional streams with the same ids; stream 0 is the
  control stream. No unidirectional streams (`initial_max_streams_uni` = 0 on both sides).
  The server SHOULD set `initial_max_streams_bidi` to `MAX_STREAMS` (128); the client sets it to
  0 (qsh/1 has no server-initiated channels) and MAY raise it later with MAX_STREAMS when a
  negotiated capability needs it.
- **Errors**: a connection error is sent as CONNECTION_CLOSE of type 0x1d (application) with the
  qsh error code (section 11.2) and the ERROR message as reason phrase; a stream error that
  cannot be sent as an ERROR message uses RESET_STREAM and STOP_SENDING with the qsh error code.
- **0-RTT**: MUST NOT be used. Clients MUST NOT send early data; servers MUST NOT accept it.
- **Session resumption**: servers SHOULD NOT send NewSessionTicket messages and clients MUST NOT
  attempt resumption; every handshake authenticates the pinned certificate.
- **Migration**: servers MUST NOT send `disable_active_migration` and MUST support connection
  migration and NAT rebinding with path validation [RFC 9000, section 9]. This is what keeps a
  session's connection alive across Wi-Fi and cellular. Clients migrate when their network
  changes (section 12.4).
- **Address validation**: the server MUST respect the anti-amplification limit of RFC 9000,
  section 8. It MUST send Retry packets while more than half of `MAX_PREAUTH_CONNS` connections
  are unauthenticated (section 6.6).
- **Recommended transport parameters and settings**:

  | Setting | Recommended value | Why |
  |---|---|---|
  | `max_idle_timeout` | 60 s | rides out a network switch; the session layer recovers beyond it |
  | client keep-alive (QUIC PING) | 20 s without packets, adapted per network (section 12.4) | keeps NAT mappings |
  | `initial_max_streams_bidi` | server 128, client 0 | sessions per connection |
  | `initial_max_stream_data_bidi_*` | ≥ 256 KiB | throughput at high RTT |
  | `initial_max_data` | server ≤ 64 KiB (REQUIRED, section 6.6), raised with MAX_DATA to ≥ 1 MiB once authenticated | pre-auth memory |
  | `max_datagram_frame_size` | absent | datagrams are not used |
  | congestion control | BBR | long, lossy paths |

### 9.2 TLS over TCP

TLS 1.3 [RFC 8446] over TCP, used where UDP is blocked or throttled.

- Both endpoints MUST negotiate TLS 1.3 and MUST NOT negotiate an earlier version.
- ALPN, certificate verification and Server Name Indication as for QUIC (section 9.1).
- 0-RTT and session resumption as for QUIC: not used.
- The mux layer (section 8) starts with the first byte of application data in each direction;
  there is no preface.
- Endpoints SHOULD set `TCP_NODELAY`; keystrokes must not wait for Nagle's algorithm.
- The server's `tcp` port is by default the same number as its `udp` port.

### 9.3 The ssh pipe

The client runs `qsh-server pipe` on the server over the user's ssh (section 10.5). The ssh
connection's stdin and stdout form one byte stream: after the server's preface, the mux layer
runs on it exactly as over TLS. ssh provides confidentiality, integrity and authentication of
the server (known_hosts) and of the user; there is no TLS inside it, so the channel binding uses
the server nonce (section 6.2) and the version is chosen on the command line of
`qsh-server pipe` (sections 5.4 and 10.5).

The pipe works wherever ssh works (ProxyJump, bastions, only port 22 open), at the cost of TCP's
head-of-line blocking and no connection migration.

### 9.4 Certificate and pinning

The daemon has one long-term key pair and a self-signed X.509 certificate for it, created on its
first start and kept in its state directory (see [security.md](security.md)).

- Key type: ECDSA P-256 with SHA-256 (RECOMMENDED) or Ed25519. The certificate's subject,
  names, validity period and extensions carry no meaning in qsh.
- The certificate fingerprint is `SHA-256(DER encoding of the certificate)`, sent in the
  bootstrap reply as `cert_sha256`, 64 lowercase hex digits (section 10.4).
- The server MUST send exactly that certificate as its only certificate in the TLS handshake,
  on QUIC and on TLS over TCP.
- The server MUST NOT request a client certificate.

The client MUST:

1. compute SHA-256 of the end-entity certificate's DER encoding and compare it, in constant
   time, with the fingerprint from the bootstrap reply; any difference MUST abort the handshake
   with the TLS alert `bad_certificate` (not some other alert, and not a later close: the
   client sends nothing to a server whose certificate it rejected, and reports the failure as a
   pin mismatch, distinct from a network failure);
2. verify the handshake's CertificateVerify signature with the public key of that certificate,
   as TLS 1.3 requires (a fingerprint match alone proves nothing: anyone can send the
   certificate);
3. ignore the certificate's names, validity dates, key usages and any further certificates;
4. never fall back to other trust: no Web PKI, no system trust store, no trust on first use, no
   option to "accept anyway". The only source of a pin is a bootstrap reply received over ssh.

A pin mismatch means the daemon's identity changed (it was reinstalled, its state was deleted, or
another program holds the port) or an attack. The client SHOULD tell the user so in one line and
obtain a new pin by bootstrapping over ssh (op `attach` keeps the session, section 10.3); it MUST
NOT retry the old pin in a loop.

A server MAY replace its key and certificate (for example on a schedule or after a suspected
compromise); clients then re-bootstrap as above.

## 10. Bootstrap over ssh

### 10.1 Overview

The bootstrap is how a client obtains everything else: it runs `qsh-server bootstrap` on the
server through the user's own ssh client, with the user's own configuration (`~/.ssh/config`,
keys, agent, known_hosts, ProxyJump, passwords, second factors). The request goes on stdin and
the reply comes on stdout; neither ever appears in a command line.

```
ssh -T [the user's ssh options] host <discovery command for "bootstrap">
  stdin:  {"qsh":1,"op":"new","versions":[1],"cols":120,"rows":40,"term":"xterm-256color",...}\n
  stdout: {"qsh":1,"versions":[1],"session":"…","key":"…","cert_sha256":"…","udp":60443,...}\n
```

The client SHOULD pass `-T` (no pseudo-terminal: stdout stays clean and binary-safe; password
and second-factor prompts still use the controlling terminal) and the user's ssh options
unchanged. It does not use `BatchMode` when it runs on a terminal, so that interactive
authentication works. It SHOULD add `-o ClearAllForwardings=yes -o ForwardAgent=no
-o ForwardX11=no`: forwardings configured for interactive logins have no use here, would fail
on ports already bound by the user's other ssh sessions, and an agent forwarded to the server
only widens its exposure.

### 10.2 Discovering qsh-server, and exit code 42

ssh passes the remote command to the user's login shell, which may be any shell (bash, zsh,
fish, tcsh, …), and the non-interactive `PATH` often lacks `~/.local/bin`, where `qsh install`
puts the server. The client therefore SHOULD send exactly this remote command, as a single
argument after the destination, with `<SUB>` replaced by `bootstrap` or by `pipe --version N`:

```
sh -c 'for p in "$(command -v qsh-server)" "$HOME/.local/bin/qsh-server"; do if [ -n "$p" ] && [ -x "$p" ]; then exec "$p" <SUB>; fi; done; exit 42'
```

It is a single-quoted POSIX `sh` program, parsed the same way by bash, zsh, dash, ksh, fish, tcsh
and csh: it contains no `!` (csh history expansion), no backslash (fish treats `\'` inside
single quotes as an escape), no newline and no single quote; any change to it MUST keep these
properties. It looks for `qsh-server` in `PATH`, then in `~/.local/bin`, and exits with status
**42** when there is none. Server implementations MUST NOT use exit status 42 for anything else
in `bootstrap` and `pipe`, so 42 always means "no qsh-server on this host". A client SHOULD also
treat 127 (command not found from the user's shell) as no qsh-server, and 126 as "qsh-server is
there but cannot be executed" (for example a binary for another architecture), which it reports
as such. Status 255 means ssh itself failed (ssh has then written the reason to stderr, which
the client shows unchanged).

### 10.3 The request

The request is one JSON object [RFC 8259], UTF-8, on a single line ending with `\n`, at most
65 536 bytes. The client writes it to the ssh process's stdin and then closes stdin. The server
reads stdin up to the first `\n` or end of file and MUST reject a longer request
(`bad-request`). Members whose names the server does not know MUST be ignored.

| Member | Type | Ops | Meaning |
|---|---|---|---|
| `qsh` | integer | all, REQUIRED | bootstrap format version: 1 |
| `op` | string | all | `new` (default), `attach`, `list`, `kill` |
| `versions` | array of integers | `new`, `attach`, REQUIRED | protocol versions the client supports |
| `command` | string or null | `new` | the remote command, as ssh would pass it to the shell; absent or null: a login shell |
| `tty` | boolean | `new` | `false`: create a pipe session (section 7.14); absent or `true`: a tty session |
| `cols`, `rows` | integers, 1–65 535 | `new`, REQUIRED for a tty session | initial terminal size; ignored for a pipe session |
| `term` | string, ≤ 64 bytes | `new` | value of `TERM`; ignored for a pipe session |
| `env` | object of strings | `new` | locale and color variables, see below |
| `name` | string, ≤ 64 bytes | `new` | optional session name, shown by `qsh ls` |
| `session` | string, 32 hex digits | `attach`, `kill`, REQUIRED | session id |
| `client` | string, ≤ 64 bytes | all | client implementation, informative |

Operations:

- **`new`** creates a session and returns its credentials.
- **`attach`** issues new credentials for an existing session (when the client lost its key,
  or the certificate pin changed): it replaces the session's current and pending keys with one
  fresh current key, ends the session's attachment if it has one (SESSION_TAKEN_OVER), and
  returns the same reply as `new`. The ssh login is the authorization.
- **`list`** returns the user's sessions on this daemon.
- **`kill`** ends a session as HANGUP does (section 7.11).

`env`: the server MUST ignore every name except `LANG`, `LANGUAGE`, `COLORTERM` and names
starting with `LC_`, and MUST ignore values longer than 256 bytes or containing a NUL byte.

`tty`: a value other than a boolean is `bad-request`. When to ask for a pipe session is the
client's choice; `qsh` asks for one when its standard input is not a terminal (ssh does not
allocate a pseudo-terminal then either). A server conforming to this document MUST support both
kinds.

The new session runs the user's login shell (from the user database) as a login shell, or
`<login shell> -c <command>`, in the user's home directory: a tty session on a new
pseudo-terminal of the requested size, a pipe session with pipes (section 7.14). Either way the
program is the leader of a new session and process group (section 7.11).

The daemon builds the session's environment from scratch; it does not pass on its own. The
environment contains exactly:

- `HOME`, `USER`, `LOGNAME` and `SHELL`, from the user database;
- `PATH`, set to a default (for example `/usr/local/bin:/usr/bin:/bin`);
- for a tty session, `TERM` (from `term`; a server MAY fall back to `xterm-256color` when the
  requested type has no terminfo entry on the host, and uses `xterm-256color` when `term` is
  absent); a pipe session has no `TERM`, as with ssh;
- the accepted `env` members;
- `QSH_SESSION`, the session id in lowercase hex;
- `XDG_RUNTIME_DIR`, when the daemon knows it.

Nothing else: not the daemon's own environment, not `/etc/environment` or other system login
configuration, and in particular not the ssh variables of the ssh login that started the
daemon (`SSH_CONNECTION`, `SSH_CLIENT`, `SSH_TTY`, `SSH_AUTH_SOCK`), which describe another,
possibly closed, connection. The rest of a login environment comes from the shell itself: a
login shell reads its own profile files (`/etc/profile`, `~/.profile`, …), which is where
systems configure `PATH`, `TZ`, `MAIL` and the like.

### 10.4 The reply

`qsh-server bootstrap` writes to stdout a `\n` (which ends any unterminated text a shell
start-up file may have printed before it), then exactly one line: one JSON object followed by
`\n`, and nothing else. Members whose names the client does not know MUST be ignored.

Reply to `new` and `attach`:

| Member | Type | Meaning |
|---|---|---|
| `qsh` | integer | 1 |
| `versions` | array of integers | protocol versions the server supports |
| `session` | string, 32 lowercase hex digits | session id (16 bytes) |
| `key` | string, 64 lowercase hex digits | session key (32 bytes) |
| `cert_sha256` | string, 64 lowercase hex digits | SHA-256 of the daemon's certificate (section 9.4) |
| `udp` | integer | QUIC port, 0 if the daemon does not listen on UDP |
| `tcp` | integer | TLS port, 0 if the daemon does not listen on TCP |
| `caps` | array of strings | capabilities the server supports (informative; negotiation is in the hello exchange) |
| `server` | string | server implementation, informative |
| `tty` | boolean | `false` for a pipe session (section 7.14), REQUIRED then; absent or `true` for a tty session |
| `ssh_addr` | string, optional | the server address of the ssh connection (from `SSH_CONNECTION`); the client MAY try it as an additional address for QUIC and TLS |

Example (one line, wrapped here):

```
{"qsh":1,"versions":[1],"session":"00112233445566778899aabbccddeeff",
 "key":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
 "cert_sha256":"5f1c…(64 hex digits)…","udp":60443,"tcp":60443,"caps":[],
 "server":"qsh-server/0.1.0"}
```

Reply to `list`:

```
{"qsh":1,"sessions":[{"session":"<32 hex>","name":"build","command":null,"created":1791200000,
  "attached":false,"exited":false}]}
```

(`created` is seconds since the Unix epoch; `command` is null for a login shell; an entry for a
pipe session has `"tty":false`, an entry without `tty` is a tty session.)

The session kind in a reply is authoritative: the client uses the layouts of section 7.14.2 if
and only if the reply to `new` or `attach` said `"tty":false`, and records the kind with the
credentials. A client that asked for a pipe session and gets a reply without `"tty":false` is
talking to a server that ignored the member; it MUST treat the session as a tty session, and MAY
end it with op `kill` and report that the server does not support pipe sessions.

Reply to `kill`: `{"qsh":1,"ok":true}`.

Error reply, for every op:

```
{"qsh":1,"error":"<code>","message":"<one line for people>"}
```

| `error` | Meaning |
|---|---|
| `bad-request` | the request is not valid JSON, too long, or misses a required member |
| `unsupported` | no common protocol version, or an unknown `op` or bootstrap format version |
| `no-session` | `attach` or `kill` of a session that does not exist |
| `limit` | the daemon has reached its limit of sessions |
| `daemon` | the daemon could not be started or reached |
| `internal` | anything else |

Exit status of `qsh-server bootstrap`: 0 after a success reply, 1 after an error reply, 2 when it
was invoked wrongly (it still writes an error reply if it can). 42 is reserved (section 10.2).

**Client processing.** The client reads stdout to its end and uses the **last** line that
parses as a JSON object with a member `qsh`; it ignores other lines, which shell start-up files
sometimes print. Its memory for this is bounded: it MUST NOT buffer more than 1 MiB of ssh's
stdout (it can process lines as they arrive, keeping only the latest candidate, and ignore
lines longer than 65 536 bytes), but it MUST keep reading and discarding until end of file or
until ssh exits, never stop reading early, because ssh blocks, and the bootstrap never
finishes, when its stdout pipe is full. It then checks `qsh` = 1, the lengths and hex syntax of
`session`, `key` and `cert_sha256`, chooses the highest version in both its own and the server's
`versions`, and treats any failure as an error. It stores the credentials (in `qsh`,
`$XDG_STATE_HOME/qsh/sessions/`, mode 0600) and connects.

**Server processing.** `qsh-server bootstrap` makes sure the user's daemon runs, starting it if
needed, then hands the request to it over the daemon's local control socket and prints the
answer. A daemon started this way MUST detach from the ssh session: new session (`setsid`), and
standard input, output and error not connected to the ssh channel. Otherwise ssh waits for the
daemon to exit and the bootstrap never completes. The control socket protocol between
`qsh-server` processes of one installation is implementation-specific and not part of qsh/1;
its security requirements are in [security.md](security.md).

### 10.5 `qsh-server pipe`

The client starts the ssh transport with the discovery command of section 10.2 for `pipe`. The
client SHOULD use `-T` and, because no person is there to answer prompts during a reconnect,
`-o BatchMode=yes`; it SHOULD also set `-o ConnectTimeout=10 -o ServerAliveInterval=10
-o ServerAliveCountMax=2`, so that a dead ssh connection is noticed and a hanging TCP connect
does not pile up processes, and the forwarding options of section 10.1.

`qsh-server pipe --version N` connects to the user's daemon (starting it if needed, as
bootstrap does), writes the **pipe preface** for version N to stdout, and then relays bytes
between its stdin/stdout and the daemon, which treats the connection as an ssh pipe transport
of protocol version N. `--version` absent means 1. If it does not support version N, it writes
nothing to stdout, one line to stderr, and exits with status 1.

```
Pipe Preface = "\nQSH-PIPE/" <N in decimal> "\n"
version 1:     "\nQSH-PIPE/1\n"   (12 bytes: 0a 51 53 48 2d 50 49 50 45 2f 31 0a)
```

- The client discards everything it reads before the preface and gives up when it has not found
  the exact preface for the version it requested within the first 65 536 bytes. The leading
  `\n` ends any unterminated text that shell start-up files printed, so the preface is always
  recognizable.
- After the preface, both directions carry mux frames (section 8). The client MAY start sending
  (CLIENT_HELLO on stream 0) before it has seen the preface.
- If the daemon was not running, `pipe` starts it; the client's ATTACH then fails with
  SESSION_UNKNOWN and it bootstraps a new session, instead of retrying a transport with nothing
  behind it.
- Exit status: 0 when either side closed the stream, 1 on errors (including an unsupported
  version), 42 reserved (section 10.2).

## 11. Errors

### 11.1 Connection and stream errors

- **Connection error**: the endpoint sends ERROR on the control stream if it can, then closes
  the connection: over QUIC with CONNECTION_CLOSE carrying the same code (section 9.1), over the
  mux layer as in section 8.6. All channels of the connection end; sessions keep running.
- **Stream error**: the endpoint sends ERROR on the stream and finishes it, or, when it cannot,
  resets it with the code (section 4.4). Other streams continue.
- Errors in the framing of a stream's messages (FRAME_ERROR, MESSAGE_TOO_LARGE) leave the rest of
  that stream unparseable, so the endpoint resets the stream instead of sending ERROR on it.
- Errors in the mux layer are always connection errors.
- An endpoint MAY close the connection instead of handling any stream error separately.

### 11.2 Error codes

| Code | Name | Scope | Meaning | What a client does |
|---|---|---|---|---|
| 0x00 | NO_ERROR | any | orderly close | — |
| 0x01 | PROTOCOL_VIOLATION | any | the peer broke a rule of this specification | report a bug, reconnect |
| 0x02 | FRAME_ERROR | any | malformed message or mux frame | as above |
| 0x03 | MESSAGE_TOO_LARGE | any | `Length` above the limit (section 3.2) | as above |
| 0x04 | UNSUPPORTED_VERSION | connection | no common protocol version | bootstrap again; tell the user to upgrade |
| 0x05 | FLOW_CONTROL_ERROR | connection | mux credit exceeded (section 8.3) | report a bug, reconnect |
| 0x06 | STREAM_LIMIT | connection | too many streams | as above |
| 0x07 | TIMEOUT | connection | hello or authentication deadline missed (section 6.6), or nothing received for too long (section 12.5) | reconnect |
| 0x08 | LIMIT_EXCEEDED | connection | pre-authentication or rate limit | back off, reconnect later |
| 0x09 | INTERNAL_ERROR | any | the sender failed | reconnect with back-off |
| 0x0a | SHUTDOWN | any | the server is stopping | reconnect later; sessions may be gone |
| 0x0b | IDLE | connection | closed for lack of use (section 12.5) | reconnect when needed |
| 0x0c | UNKNOWN_CHANNEL | stream | first message of a stream not understood (section 4.3) | do not use that feature |
| 0x0d | CANCELLED | stream | the sender abandoned the stream (for example an ATTACH that took too long, section 7.2) | — |
| 0x10 | SESSION_UNKNOWN | stream | no such session (ended, or the daemon restarted) | bootstrap a new session |
| 0x11 | AUTH_FAILED | stream | the proof matches no valid key | bootstrap op `attach` |
| 0x12 | SESSION_TAKEN_OVER | stream | a newer attachment took the session | stop; do not re-attach automatically |
| 0x13 | SESSION_ENDED | stream | the session was ended (HANGUP, `kill`, TTL, daemon shutdown) without an exit status to report, or with its output truncated | exit |
| 0x14 | SEQUENCE_ERROR | stream | offsets or acknowledgements inconsistent (section 7) | attach once more; then give up on the session |

A client receiving SESSION_TAKEN_OVER MUST NOT re-attach automatically: two clients doing so
would take the session from each other forever. (A client that itself moved the session to a
new connection ignores this error on the old stream.)

## 12. Connection management

This section describes client and server behaviour that is not needed for interoperability but
that makes qsh work well on real networks. It records what the first implementation (TokenSSH
Link) learned on phones. Values are RECOMMENDED defaults.

### 12.1 Racing transports

The client starts the transports' handshakes with staggered delays and takes the connections
in the order in which their handshakes complete (the TLS handshake for QUIC and TLS, the
preface for the pipe). On the first one it sends CLIENT_HELLO and waits up to 5 s for
SERVER_HELLO. If SERVER_HELLO arrives and is acceptable, **the race ends**: that connection is
used, and the client drops every other connection and attempt. If the hello fails or times out,
the client closes that connection and moves to the next one to complete its handshake, with
its own 5 s. Connections that complete while the client is waiting are kept as standby without
sending anything on them. (A standby connection that stays unused for 10 s is closed by the
server's `HELLO_TIMEOUT`; the client simply drops it.) The race fails when every transport has
failed or timed out.

The client then sends its ATTACHes on the winning connection only. An ATTACH that gets neither
ATTACHED nor ERROR within 5 s is abandoned (its stream reset with CANCELLED, section 7.2); the
client then treats the connection as failed and reconnects (section 12.2), racing again. The
race thus decides only which path answers; authentication is never raced, which keeps the rule
of one outstanding ATTACH per session (section 7.2) trivially true.

| Transport | Start | Attempt timeout |
|---|---|---|
| QUIC | at once | 8 s |
| TLS | after 400 ms (QUIC gets a head start: only QUIC survives address changes) | 8 s |
| ssh pipe | after 3 s, if neither QUIC nor TLS has succeeded | ssh's own `ConnectTimeout` (10 s) |

With path memory (M2), a client starts with the transport and port that worked last on the
current network and skips transports known to be blocked there, re-probing them in the
background.

### 12.2 Reconnecting

- After a connection that worked for at least 10 s ends, reconnect at once.
- After a failed attempt, or a connection that ended within 10 s, back off: 1 s, doubling to 30 s,
  with ±20 % jitter. A transport that connects and then fails the hello or the attach (for
  example a pipe to a host whose daemon is gone) counts as failed; without back-off it would
  spawn an ssh process every few seconds.
- When the network changes (section 12.4), retry at once, regardless of back-off.

### 12.3 Detecting dead paths

A path can fail without any error (NAT state lost, Wi-Fi that is associated but passes nothing).
The client declares the connection dead and races again when:

- nothing at all has been received on the connection for 45 s (the client sends PING every 15 s
  when nothing else is sent, so a live path always produces traffic); or
- the user typed, the client sent INPUT, and nothing at all has been received for 8 s since.
  The server acknowledges input within 200 ms (section 7.5) and keeps reading the stream even
  when the program does not read its terminal (section 7.4); in addition, when INPUT has been
  unacknowledged for 1 s, the client sends a PING, so the PONG on the control stream answers
  even if the terminal stream is held up by flow control; or
- over QUIC, the QUIC idle timeout fires.

A connection that is dead for one session is dead for all sessions it carries: a client that
shares a connection between sessions closes it once, and all sessions resume on the new one.

### 12.4 Network changes and NAT keepalive

- The client watches its default route and addresses (netlink on Linux, route sockets on BSD
  and macOS). When they change, it migrates QUIC connections to a new socket at once, and
  replaces TLS and pipe connections, which cannot move.
- Path memory keys a network by interface, gateway and the public address PATH_INFO reports.
- NAT keepalive learning: start with a QUIC keep-alive of 20 s. When PATH_INFO reports a new
  address or port although the client did not migrate, a NAT dropped the mapping: halve the
  keep-alive interval for that network (minimum 5 s).

### 12.5 Server housekeeping

- The server closes a connection that carries no attachment for 60 s (GOAWAY with IDLE). A
  client that keeps a connection per server for several sessions (a hub) reopens it when
  needed.
- Over the mux layer (TLS and the ssh pipe), which has no transport idle timeout of its own, the
  server closes a connection on which it has received nothing for 90 s (ERROR with TIMEOUT, or
  simply closing it). Clients send PING every 15 s when idle (section 12.3), so this only
  removes connections whose peer is gone. Over QUIC, `max_idle_timeout` does the same.
- The server applies the session TTLs of section 7.13 and the limits of section 6.6.
- A daemon started on demand (by `bootstrap` or `pipe`) SHOULD exit after 1 hour with no
  sessions; the next bootstrap or pipe starts it again. A daemon run by a service manager MAY
  stay running.

### 12.6 Ports

The daemon listens on UDP and TCP on the first port of 60443–60542 on which it can bind both
(the same number), so every user of a shared host gets their own daemon and port; the bootstrap
reply tells the client which. It SHOULD listen on IPv6 and IPv4 (a dual-stack socket, or two
sockets). Extra ports (for example 443 where the administrator allows it) are reserved for port
fallback (M2) and will be announced by additional bootstrap reply members.

## 13. Extensibility and versioning

### 13.1 Versions

The protocol version names the wire format: message framing, the mux layer, the layouts of the
messages defined here and the authentication. Version 1 is `qsh/1` in ALPN, `--version 1` and
`QSH-PIPE/1` on the pipe, and 1 in CLIENT_HELLO. A new version is needed only for an
incompatible change; it gets the ALPN id `qsh/<n>`. The version is fixed by the transport before
the first message (section 5.4): over QUIC and TLS the client offers the ALPN ids of every
version it supports and the server picks the highest common one; over the pipe the client picks
the highest version listed in both its own set and the bootstrap reply. The bootstrap request
lists the client's versions too, so that a server can refuse an incompatible client early.

The bootstrap JSON has its own format version (`"qsh": 1`), changed only for incompatible
changes; new members can be added without changing it, since unknown members are ignored.

### 13.2 Compatible extensions

Within version 1, extensions use:

- **capabilities** (section 5.4) to agree on optional features;
- **new message types**, which receivers ignore on established channels (section 3.4);
- **new channel kinds**, identified by a new first message, which receivers that do not know
  them refuse with UNKNOWN_CHANNEL (section 4.3);
- **appended fields** at the end of fixed-layout payloads, which receivers ignore (section 3.3);
- **new flag bits**, which receivers ignore;
- **new error codes**, which receivers treat like INTERNAL_ERROR when they do not know them;
- **new bootstrap members**, which receivers ignore.

Every extension that changes what a peer must do is gated by a capability; nothing new is sent
to a peer that has not shown it understands it.

## 14. Registries

The registries below are maintained in this document. New standard entries are added by a
change to this document, reviewed in the qsh repository ("specification required"). Private
ranges need no registration and MUST only be used after a private capability (a name with a
`.`) was negotiated.

### 14.1 Message types

| Range | Use |
|---|---|
| 0x00 | reserved, never sent |
| 0x01 – 0x0f | connection-level messages (control stream), section 3.5 |
| 0x10 – 0x1f | terminal channel, section 3.5 (0x1f unassigned) |
| 0x20 – 0x27 | port forwarding, capability `forward` (M3) |
| 0x28 – 0x2f | file copy, capability `copy` (M3) |
| 0x30 – 0x37 | agent forwarding, capability `agent` |
| 0x38 – 0x2fff | unassigned, specification required |
| 0x3000 – 0x3fff | private use |
| 0x4000 and above | unassigned, specification required |

Assigned types are listed in section 3.5.

### 14.2 Error codes

| Range | Use |
|---|---|
| 0x00 – 0x14 | section 11.2 (0x0e – 0x0f unassigned) |
| 0x15 – 0x2fff | unassigned, specification required |
| 0x3000 – 0x3fff | private use |
| 0x4000 and above | unassigned, specification required |

### 14.3 Capabilities

| Name | Reference | Status |
|---|---|---|
| `zstd` | section 7.12 | reserved, M2 |
| `snapshot` | section 7.8 | reserved, M2 |
| `forward` | — | reserved, M3 |
| `copy` | — | reserved, M3 |
| `agent` | — | reserved |
| names containing `.` | — | private |

### 14.4 Mux frame types

| Type | Name |
|---|---|
| 0x00 | DATA |
| 0x01 | FIN |
| 0x02 | RESET |
| 0x03 | WINDOW |
| 0x04 | CONN_WINDOW |

Not extensible within a protocol version (section 8.1).

### 14.5 Other identifiers

| Identifier | Value |
|---|---|
| ALPN id, version 1 | `qsh/1` |
| TLS exporter label | `EXPORTER-qsh-attach` |
| Pipe channel binding label | `qsh/1 pipe attach` |
| Pipe preface, version 1 | `\nQSH-PIPE/1\n` |
| Pipe version argument | `qsh-server pipe --version N` |
| Bootstrap format version | 1 |
| Bootstrap ops | `new`, `attach`, `list`, `kill` |
| Session kinds (bootstrap member `tty`) | `true` (default): tty session; `false`: pipe session |
| Bootstrap error codes | `bad-request`, `unsupported`, `no-session`, `limit`, `daemon`, `internal` |
| Exit status "no qsh-server" | 42 |
| Default port range | 60443 – 60542, UDP and TCP |

## 15. Security considerations

The threat model, the assets and adversaries, and the reasoning behind each mechanism are in
[security.md](security.md). In short:

- The trust anchor is the user's ssh. The certificate fingerprint and the session credentials
  are only ever obtained over ssh; there is no CA, no trust on first use, and no new long-lived
  secret.
- Every connection authenticates the server by its pinned certificate (section 9.4) and the
  session by a proof bound to the connection's TLS exporter (section 6); the session key never
  crosses the wire and rotates on every attach (section 6.5).
- Unauthenticated peers are confined, from the moment their connection is accepted, to 16 KiB
  read, 64 KiB buffered, a few seconds and a handful of connections per address and per daemon
  (section 6.6), and receive nothing but a hello.
- Control-socket trust is mutual: the daemon checks its local clients' user id, and every local
  client checks the runtime directory and the daemon's user id before it talks to it
  (security.md, section 4.3).
- Nothing runs as root; the daemon runs as the user and only ever starts processes as that user.
- Implementations MUST parse every message defensively: check `Length` before allocating, check
  every offset and count, and never trust a peer's value as a size without a bound. Every parser
  in the reference implementation is fuzzed.

## Appendix A. Worked example and test vectors

### A.1 CLIENT_HELLO

A client offering version 1 and the capabilities `zstd` and `snapshot`, implementation
`qsh-core/0.1.0`:

```
01                         Type = CLIENT_HELLO
20                         Length = 32
01                         Version Count = 1
01                           Version = 1
02                         Capability Count = 2
04 7a 73 74 64               "zstd"
08 73 6e 61 70 73 68 6f 74   "snapshot"
0e 71 73 68 2d 63 6f 72 65   Implementation, 14 bytes: "qsh-core/0.1.0"
   2f 30 2e 31 2e 30
```

Over QUIC these 34 bytes are the first bytes of stream 0. Over TLS or the pipe they travel in a
mux DATA frame:

```
00                         Frame Type = DATA
00                         Stream ID = 0
22                         Length = 34
01 20 01 01 02 04 7a 73 74 64 08 73 6e 61 70 73 68 6f 74 0e 71 73 68 2d 63 6f 72 65 2f 30 2e
31 2e 30
```

(Capabilities whose semantics are still reserved are shown here only to illustrate the
encoding; section 5.4 forbids offering them until they are specified.)

### A.2 ATTACH

Re-attaching session `00112233445566778899aabbccddeeff` after having received 4 096 bytes of
output, on a 120 × 40 terminal, with no flags (the client has stream state, and snapshots are
not offered), with the proof from A.4:

```
10                         Type = ATTACH
40 41                      Length = 65 (two-byte varint)
00 11 22 33 44 55 66 77    Session ID
88 99 aa bb cc dd ee ff
0c 95 bd 8b dd 96 00 4e    Proof
c3 f8 4f 7b cc 95 26 ee
33 49 19 25 da e7 78 d3
2b 6b 81 a4 2c 38 fe 93
00 00 00 00 00 00 10 00    Output Received = 4096
00 78                      Columns = 120
00 28                      Rows = 40
00 00                      Width Pixels = 0 (unknown)
00 00                      Height Pixels = 0 (unknown)
00                         Flags = 0
```

### A.3 OUTPUT

The server continues the output stream at offset 4 096 with `hello\r\n`:

```
14                         Type = OUTPUT
0f                         Length = 15
00 00 00 00 00 00 10 00    Offset = 4096
68 65 6c 6c 6f 0d 0a       Data = "hello\r\n"
```

On stream 4 over the mux layer:

```
00 04 11  14 0f 00 00 00 00 00 00 10 00 68 65 6c 6c 6f 0d 0a
```

### A.4 Proof test vectors

The TLS exporter value depends on the handshake, so the vectors start from a given `CB`.

TLS or QUIC (CB taken as given):

```
Session Key = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
CB          = a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
Proof       = 0c95bd8bdd96004ec3f84f7bcc9526ee33491925dae778d32b6b81a42c38fe93
Server Proof = HMAC-SHA256(Session Key, "qsh/1 attached" || CB)
            = 8ff9d481ebe0f5683b3e82707d8172e8bf8392b92d556fb9272ceecf814a2606
```

ssh pipe:

```
Session Key = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Session ID  = 00112233445566778899aabbccddeeff
Nonce       = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
CB          = SHA-256("qsh/1 pipe attach" || Nonce || Session ID)
            = 4818fc1f170f8040596b57e87868f65744f69bb3e37a93f9028eed89130a3801
Proof       = d011e9b69acaa41b9f815cab5a6e073d6caba66b8e9b1bc79d1d65a92f0d9694
```

### A.5 A resume, step by step

The session has produced 10 000 bytes of output; the server's replay buffer holds 2 000 – 9 999
(the client acknowledged up to 2 000 before it lost the connection, at a time when it had
received 6 000). The client had sent 300 bytes of input, of which the server received 250.

```
C → S  ATTACH      Output Received = 6000
S → C  ATTACHED    Input Received = 250, Output Start = 6000, Next Key = K2, Server Proof
S → C  OUTPUT      Offset = 6000, 4000 bytes (in several messages)
C → S  INPUT       Offset = 250, 50 bytes (resent)
C → S  KEY_CONFIRM Key ID = first 8 bytes of SHA-256(K2)
C → S  ACK         Received = 10000
S → C  ACK         Received = 300
```

Had the replay buffer instead held only 7 000 – 9 999 (8 MiB is the default; small numbers keep
the example readable), the server would have sent `OUTPUT_GAP From = 6000, To = 7000` before
`OUTPUT Offset = 7000`, and resized the pseudo-terminal back and forth to make the program
redraw. Its `last_ack` would have stayed at 6 000 (section 7.5): an `ACK Received = 6500` that
the client might have sent before processing the gap would still be valid, and output pacing
would count only the bytes from 7 000 on as in flight.

### A.6 KEY_CONFIRM

With `Next Key` = `K2`:

```
K2          = 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
SHA-256(K2) = 72dbb7336c767800…  (Key ID = the first 8 bytes)

12                         Type = KEY_CONFIRM
08                         Length = 8
72 db b7 33 6c 76 78 00    Key ID
```

On stream 4 over the mux layer: `00 04 0a 12 08 72 db b7 33 6c 76 78 00`.

### A.7 A pipe session

`qsh host 'sort'` with standard input from a file: the bootstrap request has `"tty":false` and
the reply `"tty":false`. The client re-attaches session `00112233445566778899aabbccddeeff`
after receiving 4 096 bytes of stdout and 100 bytes of stderr, with the proof of A.4:

```
10                         Type = ATTACH
40 49                      Length = 73
00 11 22 … ee ff           Session ID (16 bytes, as in A.2)
0c 95 bd … fe 93           Proof (32 bytes, as in A.2)
00 00 00 00 00 00 10 00    Output Received = 4096
00 00 00 00 00 00 00 00    Columns, Rows, Width Pixels, Height Pixels (ignored)
00                         Flags = 0
00 00 00 00 00 00 00 64    Error Received = 100
```

The server had received 250 bytes of input:

```
11                         Type = ATTACHED
40 58                      Length = 88
00 00 00 00 00 00 00 fa    Input Received = 250
00 00 00 00 00 00 10 00    Output Start = 4096
20 21 22 … 3e 3f           Next Key = K2 (32 bytes, A.6)
8f f9 d4 … 26 06           Server Proof (32 bytes, A.4)
00 00 00 00 00 00 00 64    Error Start = 100
```

The program writes `oops\n` to stderr:

```
1e 0d 00 00 00 00 00 00 00 64 6f 6f 70 73 0a
                           ERROR_OUTPUT, Offset = 100, Data = "oops\n"
```

The client resends its input from 250 and reaches the end of its file at 300:

```
1d 08 00 00 00 00 00 00 01 2c
                           INPUT_EOF, Offset = 300
```

The program ends with status 0 after 8 192 bytes of stdout and 105 of stderr. The server's
EXIT, after all output, and the client's final ACK:

```
19 17 00 00 00 00 00 00 20 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 69
                           EXIT, Output End = 8192, Kind = 0, Status = 0, Flags = 0,
                           Signal = "" (00), Error End = 105
15 10 00 00 00 00 00 00 20 00 00 00 00 00 00 00 00 69
                           ACK, Received = 8192, Error Received = 105
```

## Appendix B. Design rationale

**Why bootstrap over ssh.** Every server qsh will ever talk to already runs sshd, and every user
already has working ssh: keys, agents, known_hosts, ProxyJump, passwords, second factors,
certificates, corporate bastions. Reusing it means qsh adds no authentication system to audit,
no account database, no new port that accepts logins, and nothing for the user to configure;
`qsh host` works exactly where `ssh host` works. ssh is used once per session (and for the pipe
fallback); reconnecting needs no ssh, so a session survives even when port 22 is briefly
unreachable. mosh made the same choice for the same reasons.

**Why stdin for the request.** Command lines are visible to every local user through `ps` and
`/proc`; terminal names and commands can be sensitive, and the request is easy to extend. The
reply goes over the ssh channel, which is encrypted and authenticated.

**Why pinning, not a CA.** The daemon is a per-user process on an arbitrary host with no DNS
name of its own; a CA would need issuance, renewal and trust configuration on every client, and
would add a third party able to impersonate the server. ssh has already authenticated the host
(known_hosts) when the bootstrap runs, so the fingerprint it returns is exactly as trustworthy as
the ssh session. Pinning the SHA-256 of the whole certificate leaves nothing to parse or
interpret: no names, no dates, no chains.

**Why exporter-bound proofs.** Sending the session key, even inside TLS, would let anyone who
terminates the TLS connection (a mistaken pin, a debugging proxy, a compromised middlebox with a
stolen pin) learn it and attach forever. A proof bound to the TLS exporter is different on every
connection: it reveals nothing about the key, cannot be replayed on another connection, and
cannot be relayed through a man in the middle, whose two TLS connections have different exporter
values. The ssh pipe has no TLS of its own but is protected by ssh; a fresh server nonce makes
its proofs single-use as well.

**Why rotate keys, and why two keys at a time.** Keys are stored on the client (so `qsh attach`
works after the client process died) and stored data leaks: backups, synced home directories,
forensic copies. Rotating on every attach bounds the usefulness of a leaked key to the time
until the legitimate client next connects. Keeping the previous key valid until the client
confirms the new one makes rotation safe against a connection lost at the worst moment; the
first implementation, which rotated without confirmation, occasionally locked clients out of
their own sessions.

**Why our own multiplexing over TCP.** Running every feature over every transport keeps the
fallbacks first class: a user behind a UDP-blocking firewall gets forwarding and copy too. The
alternatives were HTTP/2 (much larger: HPACK, settings, priorities, a dependency that brings an
HTTP stack) and yamux or SSH channels (similar size but different semantics from QUIC streams).
The qsh mux is five frame types, mirrors QUIC stream semantics and ids exactly, so the layers
above cannot tell the transports apart, and returns connection credit on demultiplexing, which
avoids the head-of-line deadlock of connection windows shared with stalled streams.

**Why a byte stream with replay instead of mosh's state synchronization.** mosh synchronizes the
screen: robust and fast to catch up, but scrollback, exact output (logs, `cat` of a file, copy and
paste of long output) and terminal features the server-side emulator does not know are lost. qsh
transports the exact bytes, so the user's own terminal does all rendering, scrollback is complete
and every terminal feature works, as with ssh. Sequence numbers and a replay buffer (as in
Eternal Terminal) make the byte stream survive disconnections.

**How smart catch-up keeps mosh's Ctrl-C advantage.** A byte stream has one weakness: after a
burst of output over a slow link, the user must wait for all of it, and an interrupt takes effect
only after the backlog drains. qsh addresses this in two steps. Output pacing (section 7.6) keeps
the backlog in the server's replay buffer instead of in network buffers, and input travels on its
own direction, so Ctrl-C reaches the program at once. Then smart catch-up (section 7.8, M2): when
the backlog exceeds a couple of seconds of the path's throughput, the server drops it and sends
the current screen (SNAPSHOT), marking the gap. The user sees the program's reaction immediately,
as with mosh, and keeps exact scrollback whenever the path can carry it.

**Why one stream per session, and one connection for many.** A connection costs a handshake and,
on phones, radio time. Carrying all sessions to one server on one QUIC connection (as TokenSSH's
hub does) makes reconnecting one handshake for all of them, and QUIC streams keep the sessions
from blocking each other.

**Why fixed binary layouts with varint framing.** The messages are few and hot (every keystroke),
fixed layouts are trivial to parse, to fuzz and to describe exactly; varint type and length
framing (as in QUIC and HTTP/3) keeps unknown messages skippable, which is all the extensibility
needed.

**Why strict sequence rules.** Within one attachment both directions are delivered in order by
the transport, so the server knows exactly what the client has. Requiring contiguous offsets (and
an explicit OUTPUT_GAP) turns every bookkeeping bug into an immediate, reported error instead of
silently duplicated or missing terminal bytes.

**Why pipe sessions, and why back-pressure for them.** A tty session is lossy by design for
data: the line discipline echoes input, turns `\n` into `\r\n`, interprets control characters,
merges stdout and stderr, and a slow client loses old output to a gap. That is right for a
screen and wrong for `qsh host cmd < in > out`, which must behave like `ssh host cmd`. An
earlier draft kept a pseudo-terminal with echo and output processing turned off; that still
merged the streams, still interpreted `^C`, `^D` and `^Z` in the input, and could still drop
output under a gap. Pipe sessions use real pipes and treat output as data: the server never
discards unacknowledged output and pushes back on the program instead, as ssh's channel windows
do, so the bytes arrive exactly and the session can still be resumed.

**Why stderr's acknowledgement rides in ACK.** The error output stream needs a sequence space,
a message for its data, acknowledgements and resume offsets. A separate ERROR_ACK message, and
separate messages for stderr's attach offsets, would each have needed a type and their own
ordering rules against ACK and ATTACHED. Appending one field to ATTACH, ATTACHED, the client's
ACK and EXIT, for pipe sessions only, uses the extension mechanism the format already has
(section 3.3), leaves every tty-session encoding unchanged byte for byte, keeps one ACK as the
complete statement of what the client has received, and needs no gap message for stderr,
because pipe sessions have no gaps. The price is that these four layouts depend on the session
kind, which both sides learn from the bootstrap and never from the connection.

**Why INPUT_EOF is repeated instead of acknowledged.** End of input is one bit at a known
offset. Making it idempotent (the same `Offset` again is a no-op) and resending it after every
resume costs a few bytes per reconnect and needs no acknowledgement state on either side.

**Why ACKs are checked against what was acknowledged, not what was sent.** The first qsh
implementation moved its acknowledgement baseline to the end of an OUTPUT_GAP when it sent the
gap; an ACK that the client had sent just before it saw the gap then looked like a decrease and
ended the attachment. A gap skips bytes, it does not acknowledge them. Keeping `last_ack` as the
highest value actually received, accepting anything between it and `sent_end`, and ignoring
stale values removes the race; pacing subtracts the skipped bytes separately.

**Why KEY_CONFIRM names the key.** A bare confirmation applies to "whatever key is pending".
If a later attach replaced the pending key before an older confirmation was processed, the
older confirmation would promote a key its sender never received, and lock out the client that
did. Eight bytes of the key's hash make the confirmation refer to exactly the key the client
stored.

**Why the race ends at the hello.** Racing ATTACHes on several connections would either send
the same session's ATTACH more than once (forbidden: concurrent attaches rotate the key under
each other) or serialize them through timeouts. SERVER_HELLO already proves that the path works
and that a qsh server answers; authenticating once, on that connection, is simpler and keeps one
outstanding ATTACH per session.

**Why pre-authentication accounting starts at accept.** A limit that starts after the TLS
handshake does not count peers that never finish it, which are exactly the cheap ones to send.
Counting from the TCP accept or the QUIC Initial bounds descriptors, handshake state and timers
too, and QUIC Retry under load makes forged source addresses pay a round trip before any state
exists. Only wrong proofs count as failures, because SESSION_UNKNOWN is what a hub legitimately
sees for every session that ended while it was away.

**Why the session environment is built from scratch.** The daemon was started by some earlier
ssh login and has that login's environment: its `SSH_AUTH_SOCK` points to an agent that may be
gone, its `DISPLAY` and `SSH_CONNECTION` describe a connection that no longer exists. Passing the
daemon's environment on would make each session depend on how the daemon happened to be
started. A fixed, minimal set plus what the login shell's own profile files set gives the same
environment every time.

**Lessons from TokenSSH Link.** The first implementation (TokenSSH Link, not wire compatible)
shaped several rules: the pre-authentication size limit (a 1 MiB frame limit let any
unauthenticated peer make the daemon allocate a megabyte), the idle-connection limit (QUIC
keep-alives held connections that never authenticated), resend chunking (one resend frame above
the frame limit dropped every connection), the dead-path timers, the back-off after transports
that connect but fail the handshake, stdin instead of argv for the request, and the
detached-daemon requirement of section 10.4.

## Appendix C. Constants

| Name | Value | Section |
|---|---|---|
| `MAX_HELLO` | 2 048 bytes | 3.2 |
| `MAX_CONTROL` | 4 096 bytes | 3.2 |
| `MAX_ATTACH` | 256 bytes | 3.2 |
| `MAX_TERMINAL` | 65 536 bytes | 3.2 |
| `MAX_STREAMS` / `MUX_MAX_STREAMS` | 128 per initiator | 4.5, 8.5 |
| `HELLO_TIMEOUT` | 10 s from acceptance, handshake included | 5.1, 6.6 |
| `AUTH_TIMEOUT` | 10 s | 6.6 |
| `MAX_PREAUTH_BYTES` | 16 384 bytes | 6.6 |
| Channel streams before authentication | 4 | 6.6 |
| QUIC `initial_max_data` before authentication | ≤ 65 536 bytes | 6.6, 9.1 |
| `MAX_PREAUTH_CONNS` (unauthenticated connections per daemon) | 64 | 6.6 |
| `MAX_PREAUTH_PER_SOURCE` (per IPv4 address or IPv6 /64) | 8 | 6.6 |
| QUIC Retry threshold | more than 32 unauthenticated connections | 6.6, 9.1 |
| AUTH_FAILED per source address | 10 per minute, burst 10 | 6.6 |
| Failed ATTACH (AUTH_FAILED) per connection without an attachment | 3 | 6.4, 6.6 |
| Failure delay | ≥ 500 ms | 6.4 |
| Output replay buffer | ≥ 1 MiB, default 8 MiB | 7.6 |
| Error output replay buffer (pipe sessions) | ≥ 64 KiB, default 1 MiB | 7.14.5 |
| Input replay buffer | ≥ 64 KiB, default 1 MiB | 7.6 |
| ACK after | 32 768 bytes or 200 ms; at most 1 s | 7.5 |
| Resend chunk | ≤ 16 384 bytes | 7.3 |
| Server input queue per session | ≥ 64 KiB, default 1 MiB | 7.4 |
| `LATEST` (`Output Received`) | 2^64 − 1 | 7.2 |
| SERVER_HELLO wait per race candidate; ATTACH answer timeout (client) | 5 s | 12.1 |
| Snapshot size | ≤ 1 MiB | 7.8 |
| `DETACHED_TTL` | 6 h | 7.13 |
| `EXITED_TTL` | 1 h | 7.13 |
| Hangup: wait for the program | 2 s | 7.11 |
| Hangup: SIGKILL to the process group (MAY) | 5 s after SIGHUP | 7.11 |
| Key ID | first 8 bytes of SHA-256(Next Key) | 6.5 |
| `MUX_MAX_DATA` | 16 384 bytes | 8.1 |
| `MUX_STREAM_WINDOW` | 262 144 bytes | 8.3 |
| `MUX_CONN_WINDOW` | 1 048 576 bytes | 8.3 |
| Bootstrap request | ≤ 65 536 bytes | 10.3 |
| Bootstrap stdout memory bound (keep draining beyond it) | 1 MiB; lines ≤ 65 536 bytes | 10.4 |
| Pipe preface search limit | 65 536 bytes | 10.5 |
| Connection without attachment closed (GOAWAY IDLE) | 60 s | 12.5 |
| Mux connection with nothing received closed | 90 s | 12.5 |
| On-demand daemon exits without sessions (SHOULD) | 1 h | 12.5 |
| Control socket request deadline | e.g. 10 s | 6.6 |

## References

- [RFC 2104] HMAC: Keyed-Hashing for Message Authentication.
- [RFC 2119] [RFC 8174] Key words for use in RFCs to Indicate Requirement Levels.
- [RFC 4254] The Secure Shell (SSH) Connection Protocol (signal names).
- [RFC 8259] The JavaScript Object Notation (JSON) Data Interchange Format.
- [RFC 8446] The Transport Layer Security (TLS) Protocol Version 1.3.
- [RFC 8878] Zstandard Compression and the application/zstd Media Type.
- [RFC 9000] QUIC: A UDP-Based Multiplexed and Secure Transport.
- [RFC 9001] Using TLS to Secure QUIC.
- [RFC 9002] QUIC Loss Detection and Congestion Control.
- [FIPS 180-4] Secure Hash Standard.
