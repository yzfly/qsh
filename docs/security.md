# qsh security model

This document describes what qsh protects, against whom, and how. It is the companion of the
protocol specification, [protocol.md](protocol.md), which defines the mechanisms referred to
here (section numbers in the form "protocol §6.5"). Requirements use the key words of BCP 14
(RFC 2119, RFC 8174) when written in capitals.

To report a vulnerability, follow [SECURITY.md](../SECURITY.md) at the root of the repository.
Please do not open public issues for security problems.

## 1. Summary

- **Trust is anchored in SSH, and only in SSH.** The client learns the server's certificate
  fingerprint and the session credentials by running `qsh-server bootstrap` over the user's own
  ssh. qsh adds no CA, no trust on first use, no accounts, no passwords and no long-lived client
  secret. If you trust `ssh host`, `qsh host` asks you to trust nothing more.
- **Every connection is authenticated both ways**: the server by its pinned certificate inside
  TLS 1.3 (QUIC or TCP) or by ssh (pipe); the session by HMAC proofs in both directions, bound to
  that very connection, so the session key never crosses the wire and a proof is useless
  anywhere else.
- **Keys rotate on every attach**, so a leaked key stops working the next time the legitimate
  client connects.
- **Nothing accepts anything before authentication** beyond a hello of at most 2 KiB, a few
  ATTACH messages of at most 256 bytes, within 10 seconds of the connection being accepted, on a
  bounded number of connections per source address and per daemon.
- **Nothing runs as root.** `qsh-server` is a per-user program, run by the user over ssh or by
  the user's service manager. It never changes its user id and starts processes only as the
  user it runs as.

## 2. Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Interactive access to the user's account | the sessions on the server | equivalent to an ssh login |
| Terminal input | client → server | passwords typed at prompts, commands |
| Terminal output | server → client, replay buffer | anything the user's programs print |
| Session key (32 bytes) | daemon memory; client state file | whoever holds it can attach to the session |
| Session id (16 bytes) | daemon memory; client state file | names a session; not sufficient to attach |
| Daemon private key | `$XDG_STATE_HOME/qsh/` on the server | whoever holds it can impersonate the daemon to clients that pinned it (but still cannot attach to sessions) |
| The user's ssh credentials | the user's ssh client and agent | qsh uses them only through the ssh program; it never reads them |
| Availability of the user's sessions | the daemon | the point of qsh is that sessions survive |

## 3. Trust anchors and assumptions

1. **The user's ssh client and the server's sshd are trusted to do their job**: authenticate the
   host (known_hosts, host certificates) and the user, and protect the channel. Whatever ssh
   accepts, qsh accepts; if the user blindly accepts an unknown host key, qsh inherits that
   decision, exactly as `scp` or `git` over ssh do.
2. **The user's account on the server is trusted**, and so is root on the server: both can read
   the daemon's memory and act as the user anyway, as with ssh.
3. **The user's account on the client is trusted**: it holds the session state files, as it holds
   `~/.ssh/`.
4. **The operating system enforces user separation**: file permissions, unix socket permissions
   and peer credentials, and process isolation between users.
5. **The cryptographic primitives hold**: TLS 1.3 as implemented by rustls with the ring provider,
   HMAC-SHA256, SHA-256, the system's random number generator (`getrandom`).

## 4. Adversaries

### 4.1 Network attacker on the path

Can observe, drop, delay, reorder, replay and modify any packet between client and server,
including during the bootstrap.

- **The bootstrap** runs inside ssh: confidential, integrity protected, and the server is
  authenticated by ssh's host key. The attacker learns neither the session key nor the pin, and
  cannot substitute either.
- **QUIC and TLS connections**: TLS 1.3 gives confidentiality and integrity. The client accepts
  only the certificate pinned from the bootstrap and verifies the handshake signature with its
  key (protocol §9.4), so the attacker cannot impersonate the daemon. If the attacker relays
  the handshake to the real daemon, it sees only ciphertext.
- **Attach proofs** are bound to the TLS exporter of the connection (protocol §6.2), which is
  different on every connection and differs between the two halves of any relayed or intercepted
  connection. A captured proof cannot be replayed or relayed. 0-RTT is disabled (protocol §9.1),
  so no application data is replayable at the TLS layer either.
- **Downgrade**: blocking UDP forces TLS over TCP, blocking that forces the ssh pipe; all three
  are fully authenticated and encrypted, so the attacker degrades performance, not security. The
  ALPN value and the protocol version are covered by the authenticated TLS handshake (the pipe:
  by ssh), and both endpoints refuse a handshake that did not negotiate `qsh/1` (protocol §9.1).
- **Connection migration**: QUIC path validation (RFC 9000 §8.2) prevents the attacker from
  redirecting a connection to an address it does not control; stateless resets need the reset
  token, which only the endpoints know.
- **Traffic analysis**: the attacker sees packet sizes and timing. Keystroke timing can leak
  information about what is typed, as with ssh and mosh; qsh/1 does not obfuscate it (section
  9). The ALPN `qsh/1` is visible in the TLS ClientHello and the ports are well known, so the
  attacker can tell that qsh is in use and block it, in which case the client falls back to the
  ssh pipe. The daemon's certificate is encrypted in TLS 1.3 and the client sends no SNI, so
  the attacker cannot tell which user's daemon is being reached beyond the port number.
- **Denial of service**: an on-path attacker can always stop the traffic. qsh's answer is that
  the session survives on the server and resumes, byte exact, when any path works again.

### 4.2 Off-path attacker

Can send packets with forged source addresses and connect to the daemon's ports from anywhere,
but cannot see traffic between client and server.

- Cannot attach: it would need a 256-bit session key, or to forge an HMAC over an exporter value
  it does not know. Session ids are 128-bit random values that never appear in clear.
- Cannot inject into or reset existing connections (QUIC packet protection and stateless reset
  tokens; TLS).
- **Amplification**: QUIC's anti-amplification limit (a server sends at most three times what it
  received from an unvalidated address, RFC 9000 §8) bounds reflection attacks; under load the
  server uses Retry to validate addresses before allocating state (protocol §9.1). An
  unauthenticated peer receives nothing but a SERVER_HELLO, a PATH_INFO and errors.
- **Resource exhaustion** is bounded by protocol §6.6, and every bound counts from the moment
  the server accepts the connection (the TCP `accept`, or the first QUIC Initial it decides to
  process), not from the end of the TLS handshake, so a peer that starts handshakes and never
  finishes them is bounded like any other:
  - at most 64 connections per daemon and 8 per source address (an IPv4 address or an IPv6 /64)
    may be unauthenticated at the same time, handshaking ones included; further ones are
    refused before any TLS work (QUIC: CONNECTION_CLOSE without state; TCP: the socket is
    closed at once);
  - above 32 unauthenticated connections, every new QUIC connection must first answer a Retry,
    so forged source addresses cannot occupy slots;
  - per connection: 10 s from acceptance to a complete hello and 10 s more to a successful
    ATTACH; at most 2 KiB of hello and 4 ATTACH streams of 256 bytes; the server reads at most
    16 KiB of stream data and the QUIC stack buffers at most 64 KiB (the connection flow control
    window, not raised before authentication);
  - three wrong proofs (AUTH_FAILED) per connection that carries no attachment, a delay of at
    least 500 ms per failure, and a per-source token bucket of 10 failures per minute, beyond
    which the source's new connections are refused.

  Each handshake still costs the daemon one signature (ECDSA P-256 or Ed25519) and a key
  exchange: hosts that expose the daemon to the whole Internet should consider a firewall rule,
  as for sshd. The daemon raises its soft file descriptor limit so that these limits, not
  descriptor exhaustion, decide when connections are refused.
- **Guessing** is not a practical attack: with a 256-bit key, the rate limits matter for CPU,
  not for the key's strength.

### 4.3 Other local users on the server

Have accounts on the same host and can run arbitrary programs, bind free ports, and look at
`ps`, `/proc` and world-readable files.

- **Per-user daemons**: every user has their own daemon, their own certificate and their own
  ports (the first free port of 60443–60542, protocol §12.6). A daemon only ever serves its own
  user's sessions, and sessions run as that user.
- **No secrets in argv or the environment.** The bootstrap request is passed on stdin, the
  reply on stdout, both through ssh (protocol §10). `qsh-server` MUST NOT put session keys,
  proofs or private keys in command lines or environment variables, of its own or of processes
  it starts, and MUST NOT log them. The session's environment does not contain the key
  (`QSH_SESSION` holds the session id only).
- **Port squatting**: another user may bind a port in the range first; the daemon takes the next
  free one, and the bootstrap reports the real port. A process of another user listening on a
  port the client remembers cannot impersonate the daemon, because of pinning. Another user can
  occupy all hundred ports and deny the direct transports; the ssh pipe still works (section 9).
- **Local files and sockets**, all created by `qsh-server` with explicit modes:

  | Path | Mode | Contents |
  |---|---|---|
  | `$XDG_RUNTIME_DIR/qsh/` | 0700 directory | runtime state |
  | `$XDG_RUNTIME_DIR/qsh/control.sock` (name implementation-defined) | 0600 socket | control socket for `bootstrap`, `pipe`, `status` and `stop` |
  | `$XDG_STATE_HOME/qsh/` (default `~/.local/state/qsh/`) | 0700 directory | persistent state |
  | `$XDG_STATE_HOME/qsh/identity.*` (names implementation-defined) | 0600 files | the daemon's private key and certificate |

  Every directory, file and socket is created with its mode given explicitly (`mkdir` and
  `open` with the mode, a socket bound inside the 0700 directory and then set to 0600), and a
  file holding a secret is written to a temporary name with mode 0600 and renamed into place.
  The daemon does **not** change its process umask to get there: the programs of every session
  inherit the daemon's umask, and a user whose files suddenly came out 0600 because they were
  created in a qsh session would rightly call that a bug. The daemon keeps the umask it was
  started with (from the ssh login or the service manager).

  Session keys exist on the server only in the daemon's memory; they are never written to disk.
- **The runtime directory is checked, by everyone who uses it.** When `XDG_RUNTIME_DIR` is not
  set (common for ssh logins on hosts without systemd-logind), the runtime directory falls back
  to `/tmp/qsh-<uid>/`, a name another user can pre-create, and even under `XDG_RUNTIME_DIR` a
  misconfiguration can leave it wrong. So:
  - the daemon creates the directory with `mkdir` mode 0700 if it does not exist;
  - **every** process that uses it, the daemon and each control-socket client alike
    (`qsh-server bootstrap`, `pipe`, `status`, `stop`, and the client hub's own clients),
    verifies with `lstat`, before it binds or connects to anything inside, that the path is a
    directory (not a symlink), owned by its effective user id, with no group or other
    permission bits. If any check fails it MUST refuse to use the directory and report the
    problem; it MUST NOT "repair" it with `chmod` or `chown`, which would make a directory
    someone else controls look trustworthy.
- **Control-socket trust is mutual.** The control socket carries session keys (in bootstrap
  replies) and whole sessions (the pipe), so both ends authenticate each other with the
  operating system's peer credentials (`SO_PEERCRED` on Linux, `getpeereid` on BSD and macOS):
  - the daemon accepts a control connection only from a peer whose user id equals its own
    effective user id;
  - every client of the socket MUST check, right after connecting and before it sends anything,
    that the peer's user id equals its own effective user id. Otherwise another user who managed
    to put a socket in its place (a race on `/tmp`, a wrong `XDG_RUNTIME_DIR`) would receive the
    bootstrap request and could answer it with credentials and a pin of its own choosing.
  - Every exchange on the socket has a deadline (protocol §6.6), so a local client that connects
    and stalls cannot pin the daemon's resources.

  The same rules apply to the client hub's socket (section 4.4).
- **Inherited file descriptors**: the daemon opens every file and socket close-on-exec, so the
  programs of a session do not inherit its listening sockets, the control socket, other
  sessions' pseudo-terminals or pipes, or the identity files.
- **Session environment**: the daemon builds each session's environment from a fixed list
  (protocol §10.3) and passes on nothing of its own environment, so nothing of the ssh login
  that happened to start the daemon (`SSH_AUTH_SOCK`, `SSH_CONNECTION`, …) leaks into later
  sessions.
- **Sessions end completely**: hanging a session up signals its process group and closes its
  terminal, and the session's id, key and buffers are removed at once (protocol §7.11); a
  session that was ended can no longer be attached by anyone, whatever its processes do.

### 4.4 Other local users on the client

- **Session state files (`qsh attach`).** They live in `$XDG_STATE_HOME/qsh/sessions/`
  (directory 0700, files 0600, both created with explicit modes; a directory or file that others
  may read, or that belongs to someone else, is refused, never quietly tightened). A state file
  holds the destination and ssh options, the daemon's host, ports and certificate fingerprint,
  the session id, the session kind and the session key; no offsets (a new client attaches with
  FRESH). The client writes them atomically (a temporary file with mode 0600 in the same
  directory, synced, renamed, then the directory synced) so a crash never leaves a truncated
  key, and stores every rotated key there before it sends KEY_CONFIRM (protocol §6.5). It
  deletes the file when the session ends or the server does not know it. A `.lock` file next to
  it is held (`flock`) by the `qsh` process using the session, which is how `qsh ls` and
  `qsh attach` tell a session in use on this machine from a detached one. Embedders that keep no
  state files (the hub) keep credentials only in memory and confirm keys at once; losing the
  process then means re-issuing the key over ssh (bootstrap op `attach`).
- The client passes nothing secret to ssh on its command line; the request goes to ssh's stdin.
- A resident client process shared by embedders (the hub, DESIGN §4) listens on a unix socket
  of mode 0600 in a 0700 directory. Trust is mutual, as for the daemon's control socket
  (section 4.3): the hub accepts only peers with its own user id, and every hub client checks
  the directory with `lstat` and the hub's peer user id before it sends anything.
- The client MUST NOT print keys or proofs in verbose or debug output.

### 4.5 A stolen state file

An attacker who obtains a copy of a client's state file (a backup, a synced or shared home
directory, a lost laptop) holds the session id, a session key and the pin.

- The key is valid only until the legitimate client next attaches: every attach rotates it, and
  once the client confirms the new key the old one is discarded (protocol §6.5). In the window
  between the server sending a new key and the client confirming it, both are valid; the window
  is one round trip in normal operation.
- A detached session lives at most 6 hours, then the session and its key are gone (protocol
  §7.13). A key never outlives its session.
- If the attacker attaches first, it takes the session over: the legitimate client receives
  SESSION_TAKEN_OVER and, unlike in a reconnect, MUST NOT re-attach automatically (protocol
  §11.2); it tells the user. The user can then end the session with `qsh kill` over ssh, which
  the attacker cannot do without the user's ssh credentials, or take it back with
  `qsh attach`, which issues a fresh key over ssh and invalidates the attacker's (protocol
  §10.3).
- The pin is not a secret.
- The state file is as sensitive as an unencrypted ssh private key for the session's lifetime.
  qsh does not encrypt it: it has to be usable without a prompt to reconnect in the background.
  This is a deliberate trade-off (section 9).

### 4.6 A malicious or compromised server

The server is the user's own account on a remote host. If it is compromised, the attacker
already has what qsh protects there. What matters is what it can do to the client:

- **Terminal output** is passed to the user's terminal unchanged, as ssh does; escape sequence
  attacks against terminal emulators are the terminal's responsibility, exactly as with ssh. The
  client's own status line and messages are not part of the output stream.
- **No access to the client.** qsh/1 has no server-initiated channels (protocol §4.3), no agent
  forwarding, no port forwarding and no file transfer; future features of this kind are opt-in
  per connection by the client (capabilities) and per use by the user.
- **Robust parsing.** Every client parser is bounded and fuzzed: message lengths are checked
  before allocation (protocol §3.2), snapshots are limited to 1 MiB and compressed frames to
  64 KiB of declared, checked output (protocol §7.8, §7.12). The client keeps at most 1 MiB of
  the bootstrap's output while it keeps draining ssh's stdout to the end (protocol §10.4), does
  all offset arithmetic checked and rejects attach offsets beyond what it sent (protocol §7.3),
  and resets with UNKNOWN_CHANNEL any stream the server opens without a negotiated reason
  (protocol §4.3).
- **ssh credentials**: the bootstrap and pipe ssh invocations disable agent and X11 forwarding
  and clear configured port forwardings (protocol §10.1), so the server gets no access to the
  user's agent through qsh even if the user's ssh configuration forwards it for interactive
  logins.
- **Lies**: the server can lie about exit codes, PATH_INFO, sessions and capabilities. These
  affect only the client's display and path heuristics, never its security decisions.

### 4.7 The daemon's identity, stolen

An attacker who obtains the daemon's private key (for example from a backup of the user's home
directory) and can intercept a client's traffic can complete the TLS handshake as the daemon.
It still cannot pose as a session: ATTACHED must carry a server proof computed with the session
key (protocol §6.3), which it does not have, and the client sends no input and stores no new key
before verifying that proof. It cannot attach to real sessions either (the client's proof is
bound to the attacker's own connection, and the key is never sent). What it gains is the
ability to make the client fail, and the session ids the client names in ATTACH. Recovery: delete the identity files (or use the
implementation's rotation command); the daemon creates a new identity, clients fail the pin and
re-bootstrap over ssh, which gives them the new fingerprint. Because the pin is replaced only
through ssh, the old identity becomes useless at once.

## 5. Mechanisms and what they defend

| Mechanism | Protocol | Defends against |
|---|---|---|
| Bootstrap over the user's ssh | §10 | impersonation of the server at first contact; a second authentication system to attack |
| Request on stdin, reply on stdout | §10.3–10.4 | other local users reading commands or keys from `ps` / `/proc` |
| Certificate pinning (SHA-256 of DER) and signature check | §9.4 | server impersonation; CA compromise (there is no CA) |
| TLS 1.3 only, no 0-RTT, no resumption | §9.1–9.2 | eavesdropping, tampering, replay of early data |
| Exporter-bound HMAC proof | §6.2–6.3 | key disclosure on the wire; replay and relay of proofs |
| Server proof in ATTACHED | §6.3, §7.3 | impersonation of a session by a holder of a stolen daemon key |
| Server nonce binding on the pipe | §6.2 | replay of pipe proofs |
| Key rotation with confirmation | §6.5 | long-lived use of leaked keys, without lockouts |
| Pre-authentication limits, counted from accept | §6.6 | memory, descriptor and CPU exhaustion by unauthenticated peers, including ones that never finish a handshake |
| ALPN required and checked on both sides | §9.1 | a qsh endpoint talking to a non-qsh TLS peer, cross-protocol confusion |
| Key ID in KEY_CONFIRM | §6.5 | a delayed confirmation promoting a key the client never received |
| QUIC address validation, Retry | §9.1 | amplification and reflection |
| Message size limits, strict parsing | §3 | memory exhaustion, parser exploits |
| Strict sequence rules | §7.4–7.5 | silent corruption of terminal streams |
| Never drop unacknowledged input | §7.6 | partial commands executed after a reconnect |
| One attachment per session, no automatic retake | §7.3, §11.2 | two clients fighting over a session; silent hijack |
| Session TTLs | §7.13 | abandoned sessions and keys living forever |
| Per-user daemon, no root | §4.3 here | privilege escalation; cross-user access |
| Socket peer credential checks on both ends, `lstat` of the runtime directory by every user of it, explicit 0700/0600 modes | §4.3 here | other local users reaching the daemon, or posing as it to local clients |
| Session environment built from a fixed list | protocol §10.3 | stale ssh agent sockets and connection variables leaking into sessions |

## 6. Cryptography

| Use | Choice |
|---|---|
| TLS library | rustls, with the ring crypto provider |
| Protocol version | TLS 1.3 only, on QUIC (RFC 9001) and TCP (RFC 8446) |
| Cipher suites | TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 (all TLS 1.3 suites; there are no weak ones to disable) |
| Key exchange | X25519, then secp256r1; a hybrid post-quantum group (X25519MLKEM768) as soon as the crypto provider in use supports it |
| Server signature | ECDSA P-256 with SHA-256 (default) or Ed25519 |
| Pin | SHA-256 over the DER certificate |
| Attach proof | HMAC-SHA256 keyed with the session key over the 32-byte channel binding value; server proof: the same over `"qsh/1 attached"` and the channel binding value |
| Channel binding | TLS exporter, label `EXPORTER-qsh-attach`, context = session id (QUIC, TLS); SHA-256 over a label, a 32-byte server nonce and the session id (pipe) |
| Random numbers | the operating system CSPRNG via ring (`getrandom`) |
| Secret comparison | constant time |

Handling of secrets in memory (session keys, the bootstrap reply that carries one, the
daemon's private key):

- Implementations SHOULD zeroize a session key when it is dropped: when it is replaced by
  rotation, when a pending key is discarded, and when the session ends (in Rust, a key type that
  overwrites itself on `Drop`, for example with the `zeroize` crate). This limits what a later
  memory disclosure (a core dump, swap, a heap read bug) can reveal; it is defence in depth, not
  a boundary, since the same user can read the daemon's memory anyway (section 9).
- Credentials MUST never appear in logs, debug output, error messages or crash reports, of the
  daemon or the client, at any verbosity: types holding keys or proofs implement their debug
  formatting (`Debug` in Rust) to print a placeholder such as `SessionKey(..)`, and the
  bootstrap reply is never logged as received. Session ids, key IDs (protocol §6.5) and
  certificate fingerprints are not secret and may be logged.
- Implementations MUST NOT write keys to core dumps or crash reports they control (the daemon
  MAY lower its own `RLIMIT_CORE` soft limit to 0, provided it restores the original limit in
  the programs it starts, so that sessions keep the user's own setting).

### Key and credential lifetimes

| Item | Created | Ends |
|---|---|---|
| TLS traffic keys | each handshake | connection close (QUIC key updates rotate them within a connection) |
| Server nonce | each connection | connection close |
| Session key | bootstrap, then each attach | confirmed replacement (one round trip after the next attach; KEY_CONFIRM names the key it confirms), `bootstrap attach`, or session end; zeroized when dropped |
| Session id | bootstrap | session end: 6 h detached, 1 h after exit, HANGUP, `qsh kill` |
| Daemon identity (key, certificate) | first daemon start | deleted or rotated by the user or administrator; implementations SHOULD offer a rotation command |
| Client state file | bootstrap | the client deletes it when the session ends or is unknown to the server |

## 7. Denial of service

- **Amplification**: QUIC's 3× limit before address validation, Retry under load; TCP has its
  own handshake; the pipe needs an ssh login. An unauthenticated peer gets nothing larger than a
  SERVER_HELLO.
- **State exhaustion**: bounded per unauthenticated connection (16 KiB read, 64 KiB buffered,
  10 s to the hello), per source address (8 connections) and per daemon (64 unauthenticated
  connections), all counted from the moment a connection is accepted, handshakes included (section
  4.2). Authenticated connections can only be opened by holders of a session key; idle mux
  connections are closed after 90 s without traffic.
- **CPU**: one TLS handshake per connection, behind Retry under load; failed attaches are
  delayed and rate limited per source address.
- **Local clients**: every control-socket request has a deadline; a stalled local process
  cannot hold the daemon.
- **Authenticated peers** are the user (or someone holding a session key). Memory per connection
  is still bounded: stream windows, `MAX_STREAMS`, message size limits, and the replay buffers
  (default 8 MiB of output per session, bounded input on the client).
- **A slow or absent client never blocks a tty session's program**: the daemon keeps reading the
  pseudo-terminal and discards the oldest output instead (protocol §7.6). A pipe session is
  data and is never truncated: there the program is blocked, as with ssh, until the client
  acknowledges its output, and memory stays bounded by the replay buffers (protocol §7.14.5).
- **Sessions per user** are limited by the daemon (bootstrap error `limit`); one user cannot use
  qsh to exhaust the host beyond what their account can do anyway.

## 8. Deployment guidance

- **No root, no setuid.** Packages install `qsh` and `qsh-server` as ordinary executables. The
  system service that would authenticate users itself (`qshd`, a later milestone) does not exist
  in qsh/1.
- **Root logins**: if an administrator logs in as root over ssh and runs qsh, the daemon runs
  as root, because it serves the account that logged in, just like that ssh session. It gains
  no privilege from this.
- **Service units**: the user unit `qsh-server.service` MUST NOT use sandboxing options that are
  inherited by the user's sessions and break them (`NoNewPrivileges=` breaks `sudo`;
  `PrivateTmp=`, `ProtectSystem=`, `ProtectHome=` change what the shell sees). The daemon is a
  login service; it is confined by the user's own permissions.
- **Firewalls**: the direct transports need UDP and TCP on the user's port in 60443–60542.
  Administrators who do not want them can leave the ports closed: qsh then uses the ssh pipe,
  which needs nothing beyond sshd. `qsh-server doctor` reports what is reachable.
- **Logout policy**: where systemd-logind has `KillUserProcesses=yes`, every process started
  from a login session, a daemon started by `bootstrap` included, is killed when that ssh login
  ends. qsh respects that policy: sessions then survive only if the daemon runs from the user
  unit with lingering enabled (`loginctl enable-linger`), which is the administrator's decision.
  `qsh-server doctor` reports the situation.

## 9. Known limitations

- **The state file is an unencrypted credential** for the lifetime of its session (section
  4.5). It is rotated on every attach and dies with the session, but between attaches anyone who
  can read the user's files on the client can attach.
- **Sessions do not survive a daemon restart** (upgrade, reboot, `qsh-server stop`): they live in
  the daemon's memory. Clients see SESSION_UNKNOWN and start a new session.
- **Keystroke timing** is not obfuscated (OpenSSH has done so since 9.5). Planned.
- **No post-quantum key exchange yet** with the ring provider; recorded traffic could be
  decrypted by a future quantum computer. qsh will enable X25519MLKEM768 when its crypto
  provider supports it.
- **qsh is identifiable on the network** by ALPN and port. It does not try to hide; the ssh pipe
  is the fallback where it is blocked.
- **All sessions of a user share one trust domain**: a program in one session can read the
  daemon's memory (same user id) and therefore other sessions' keys and output, just as it can
  read the user's ssh keys. This is not a boundary qsh tries to enforce.
- **Port range**: at most 100 users per host can use the default range at the same time; further
  users fall back to the pipe unless the administrator widens the range.
- **Trust in ssh is inherited, including its weaknesses**: blindly accepted host keys, a
  compromised ssh client, or a compromised agent compromise qsh too.
- **The pipe fallback for reconnects needs non-interactive ssh authentication** (keys, an agent,
  or a ControlMaster connection). With password-only ssh, reconnects use QUIC and TLS only.

## 10. Reporting vulnerabilities

See [SECURITY.md](../SECURITY.md) for supported versions, how to report a vulnerability
privately, and what to expect after reporting.
