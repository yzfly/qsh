# qsh design

> qsh is a modern remote shell: the SSH you already have, upgraded with QUIC.
> Sessions survive network changes, sleep and roaming; nothing to configure.

Goal: qsh becomes a **standard Linux component**, shipped by distributions next to openssh,
trusted the way ssh is trusted. Every decision below is measured against that bar.

This document is the contract for everyone working on qsh. Change it first, then the code.

## 1. Why

| | ssh | mosh | Eternal Terminal | **qsh** |
|---|---|---|---|---|
| Wi-Fi ↔ cellular, IP changes | drops | survives | survives | survives (QUIC connection migration) |
| Laptop asleep for hours | drops | survives | survives | survives, and **replays the output you missed** |
| Scrollback | yes | **no** (screen sync only) | yes | yes, byte exact |
| UDP blocked | works | **fails** | works (TCP) | races QUIC, TLS/TCP and an ssh pipe, uses whichever works |
| Typing on a 300 ms link | laggy | predictive echo | laggy | predictive echo (M3) |
| Flood of output, then Ctrl-C | slow | instant | slow | instant: smart catch-up (M2) |
| Port forwarding, file copy | yes | no | forwarding | yes, over QUIC streams (M3) |
| Server setup | sshd | mosh-server, UDP 60000-61000 open | etserver as root | `qsh-server`, no root, no config; `qsh` offers to install it |
| Maintained | yes | last release 2022 | slow | yes |

In one line: **if you can `ssh host`, you can `qsh host`, and it never drops.**

## 2. Principles

1. **Drop-in for ssh.** Same destinations, same `~/.ssh/config`, keys, agent, known_hosts, ProxyJump, passwords and 2FA. qsh never asks you to trust anything ssh does not already trust.
2. **Zero configuration, no root.** Works on every Linux distribution and macOS out of the box. Root (`qsh-server tune`) only makes it faster, never required.
3. **The session lives on the server, the connection is a replaceable pipe.** A pipe that breaks is replaced; not a byte is lost.
4. **Optimize itself.** qsh measures the path and adapts (section 7). Nobody tunes a knob to get a good connection.
5. **Quiet and honest.** No noise while things work; when they do not, one line saying what happens and what to do.
6. **An open, specified protocol and a library.** `docs/protocol.md` is a specification another team can implement from. `qsh-core` is a library other programs embed (TokenSSH is the first).
7. **Secure by construction.** Trust is anchored in SSH; no new long-lived secret, nothing runs as root, no listener accepts anything before authentication (`docs/security.md`).

## 3. The standard-component bar

What distributions and security teams expect, and qsh commits to from the first release:

- **Two programs, like openssh / mosh**: `qsh` (client) and `qsh-server` (server side, run over ssh, or as a per-user daemon). Packagers can split them into `qsh-client` and `qsh-server` packages.
- **Builds from source offline** with the distribution's Rust (MSRV declared in `Cargo.toml`, tested in CI), a small dependency tree of crates already packaged by Debian and Fedora (tokio, quinn, rustls + ring, clap, serde). `cargo deny` gates licenses and advisories. No build-time downloads, no bundled C.
- **No network access at runtime** except the protocol itself; the convenience installer (`qsh install`, downloading release binaries) is a cargo feature, `self-install`, that distribution builds turn off.
- **FHS and XDG paths**, documented: `/usr/bin/qsh`, `/usr/bin/qsh-server`, `/etc/qsh/` (system defaults), `$XDG_CONFIG_HOME/qsh/`, `$XDG_STATE_HOME/qsh/`, `$XDG_RUNTIME_DIR/qsh/`.
- **Man pages**: qsh(1), qsh-server(1), qsh_config(5), generated from the code and checked in CI. Shell completions for bash, zsh, fish.
- **Service integration**: a systemd user unit (`qsh-server.service`) and an OpenRC script; on-demand start needs neither. Logs go to stderr / journald, no log files of our own in system mode.
- **Stable interfaces**: documented exit codes, config format, protocol versions with negotiation; semver for `qsh-core`.
- **Quality**: `#![forbid(unsafe_code)]` everywhere except a small `sys` module (pty, termios, fd), each `unsafe` justified; fuzzing of every parser (cargo-fuzz, run in CI); property tests of the session layer; end-to-end tests on a distribution matrix; chaos tests with netem.
- **Faults stay local**: a bug triggered by one session's data never takes down the daemon. In particular a fault in the screen model (smart catch-up) disables catch-up for that session only; release builds unwind on panic, and the model and the codec run under `catch_unwind` (protocol §7.8.7).
- **Optional parts for older distributions**: compression is a cargo feature, `zstd` (default on; it needs `ruzstd` ≥ 0.8.1 for the encoder, our own decoder does the rest). Without it qsh neither offers nor accepts compression and everything else works; Debian 13, whose `ruzstd` 0.7.3 has no encoder, builds that way. The screen model needs `vt100` 0.16 (0.15 lacks the faint attribute and `Screen::set_size`): Debian sid has it, Debian 13 (0.15) needs it packaged or vendored ([m2.md](m2.md) §6.2, §7.3).
- **Releases**: reproducible, checksums plus signatures, `SECURITY.md` with a disclosure process, changelog.
- **Packaging kept in the repository** for upstreaming: Debian (`debian/`), RPM spec, Alpine `APKBUILD`, Arch `PKGBUILD`, Homebrew formula, plus static musl binaries on GitHub Releases.

## 4. Architecture

```
client                                                  server
┌───────────────────────────┐   ① ssh (once)     ┌──────────────────────────────────────┐
│ qsh host                  │ ─────────────────▶ │ sshd → qsh-server bootstrap          │
│  ├ connection manager     │                    │   → session id, session key, ports,  │
│  │  (race QUIC/TLS/ssh)   │                    │     certificate fingerprint (JSON)   │
│  ├ session layer          │   ② qsh/1          │ qsh-server daemon (per user)         │
│  │  (seq, ack, replay)    │ ◀════════════════▶ │  ├ sessions, by id                   │
│  └ terminal (raw mode,    │  QUIC / TLS / ssh  │  └ session → pty → shell or command  │
│     escapes, status)      │                    └──────────────────────────────────────┘
└───────────────────────────┘
```

- **Bootstrap over ssh.** `qsh host` runs the user's ssh as is (interactive: password and 2FA prompts work) with the remote command `qsh-server bootstrap`. The request (command, terminal size, TERM, locale) goes on ssh's stdin as JSON, never in argv (argv is visible to every user in `ps`). The reply on stdout is one JSON line: protocol versions, session id, session key, ports, the daemon certificate's SHA-256. The client pins exactly that certificate. Reconnecting needs no ssh.
- **Daemon.** One per user, started on demand by the bootstrap (works without any init system) or by its service unit. Listens on UDP and TCP; the port is the first free one in a range (default 60443–60542) so that every user of a shared host gets their own; the bootstrap reply says which. Plus a unix control socket in `$XDG_RUNTIME_DIR/qsh/` (mode 0700 dir) for bootstrap and the ssh pipe; trust is mutual: the daemon and every client of the socket check the directory (`lstat`) and each other's user id (`SO_PEERCRED` / `getpeereid`).
- **Transports.** QUIC (preferred), TLS 1.3 over TCP, and the ssh pipe (`ssh host qsh-server pipe`). Raced like Happy Eyeballs with staggered starts; the first connection to answer the hello wins, and the client attaches on it.
- **Session layer.** Each direction of a terminal channel has a 64-bit byte sequence and a replay buffer (8 MiB of output by default). Resume: the client says what it received, the server says what it received, both resend from there, the server rotates the session key. Beyond the buffer the gap is marked and the screen redrawn.
- **Session kinds.** A *tty session* runs on a pseudo-terminal (interactive use). A *pipe session* (bootstrap `"tty": false`, used when the client's stdin is not a terminal) runs the command with pipes for stdin, stdout and stderr, byte exact like `ssh host cmd`: stderr is its own stream, end of input is forwarded, and output is never dropped (the program is blocked instead, as with ssh).
- **Streams.** Over QUIC every channel is a native stream; over TLS and the ssh pipe a small stream-multiplexing layer with per-stream flow control carries the same channels, so every feature (forwarding, copy) works on every transport.
- **Multiplexing.** One connection per server can carry many sessions (the optional client hub, used by embedders such as TokenSSH, keeps one connection per server for all terminals).

### Protocol qsh/1 (outline, the specification is docs/protocol.md)

- ALPN `qsh/1` on QUIC and TLS. Self-signed server certificate, pinned by SHA-256 from the bootstrap.
- Messages: `type (varint) | length (varint) | payload`, QUIC-style varints, fixed binary payload layouts; unknown message types on extensible channels are ignored, so new features need no version bump.
- Connection setup on the first bidirectional stream (the control stream): `CLIENT_HELLO` (supported versions, capabilities) → `SERVER_HELLO` (chosen version, capabilities). Capabilities are named strings (`zstd`, `snapshot`, `forward`, `copy`, `agent`, …).
- Session authentication is bound to the connection and mutual: the client's proof is HMAC-SHA256(session key, TLS exporter `EXPORTER-qsh-attach` with the session id as context); ATTACHED carries the server's proof under the same key, so a stolen certificate key alone cannot impersonate a session. The key never crosses the wire. Over the ssh pipe (no TLS) a server nonce takes the exporter's place. Every attach rotates the key; the server keeps the current and the pending key until KEY_CONFIRM, which names the key it confirms (8 bytes of its SHA-256), so a connection lost at the wrong moment never locks the client out.
- Racing: the client races the transport handshakes; the race ends at the first SERVER_HELLO (5 s per candidate), then the client sends ATTACH on that connection only (one outstanding ATTACH per session; an unanswered ATTACH is cancelled after 5 s and the client reconnects).
- Terminal channel messages: `ATTACH`/`ATTACHED`, `INPUT`/`OUTPUT` with sequence numbers, `ACK` (checked against the highest ACK received, never against a gap), `OUTPUT_GAP`, `RESIZE`, `SNAPSHOT` (M2), `DETACH`, `HANGUP`, `EXIT`, `ERROR` with enumerated codes; for pipe sessions also `ERROR_OUTPUT` (stderr, its own sequence) and `INPUT_EOF`. `FRESH` attaches (a new client process) replay the server's buffer by default (`qsh attach` shows what you missed). Every attachment ends with a definite last message (EXIT, SESSION_ENDED, SESSION_TAKEN_OVER — never auto re-attach after that — or FIN after DETACH); output cut short by a hangup is announced with OUTPUT_GAP first. Hanging up signals the session's process group and closes its terminal; a daemon that stops ends every session, then sends GOAWAY, and clients do not respawn it. Connection-level: `PING`/`PONG` with timestamps for RTT, `PATH_INFO` (the address the server sees), `GOAWAY`.
- The server paces output to about two bandwidth-delay products, so a backlog stays in the replay buffer where smart catch-up can skip it.
- Pre-authentication limits, counted from TCP accept / the QUIC Initial: hello within 10 s, at most 16 KiB read (and a 64 KiB QUIC connection window) and 4 streams before authentication, 3 wrong proofs per connection without an attachment, with a delay, 64 unauthenticated connections per daemon and 8 per source address (IPv6 per /64), QUIC Retry above half of that, a per-source failure rate limit; no 0-RTT. ALPN `qsh/1` is required and checked on both sides.
- Bootstrap operations over ssh: `new`, `attach` (re-issue the key of an existing session: recovers a lost key or a changed certificate pin), `list`, `kill`. The remote lookup is a fixed `sh -c` that tries PATH and `~/.local/bin` and exits 42 when there is no qsh-server; replies and the pipe preface start with a newline so shell start-up noise cannot corrupt them.
- Session environment: built from scratch: `HOME`, `USER`, `LOGNAME`, `SHELL`, a default `PATH`, `TERM` (tty sessions), the client's `LANG`, `LANGUAGE`, `LC_*`, `COLORTERM`, `QSH_SESSION`, `XDG_RUNTIME_DIR`; nothing of the daemon's own environment (so no `SSH_*` of the login that started it) and nothing from `/etc/environment` — the login shell reads its own profile.
- The bootstrap JSON is versioned (`"qsh": 1`) and documented with the protocol.

Not wire compatible with TokenSSH Link (TLP); TokenSSH migrates both of its ends to `qsh-core` in one release.

## 5. Code layout

```
Cargo.toml                 workspace, MSRV, shared lints
crates/qsh-core/           library: everything that is not a command line
  src/lib.rs               public API
  src/paths.rs             Paths: config / state / runtime dirs, overridable by embedders
  src/proto/               wire format: varints, messages, encode / decode (fuzzed)
  src/mux.rs               stream multiplexing over byte-stream transports
  src/crypto.rs            identity, pinning, exporter proofs, TLS and QUIC configs
  src/transport/           quic.rs, tls.rs, ssh.rs: connect, accept, the race
  src/session/             replay buffer, sequence bookkeeping, resume
  src/client.rs            bootstrap, connection manager, one session
  src/server/              daemon, session table, pty, control socket, bootstrap, pipe
  src/hub.rs               optional resident client (embedders)
  src/sys.rs               the only module with unsafe: pty, termios, fds
crates/qsh-cli/            package qsh-cli, binaries `qsh` and `qsh-server`
  src/bin/qsh.rs           client command line
  src/bin/qsh-server.rs    server command line
  src/terminal.rs          raw mode, resize, escapes (~. ~d ~s ~?), status line
  tests/                   end-to-end tests with a fake ssh
fuzz/                      cargo-fuzz targets
docs/                      DESIGN.md (this), protocol.md, security.md, m2.md (M2 design and plan)
man/                       generated man pages
packaging/                 debian/, rpm/, alpine/, arch/, homebrew/, systemd/, openrc/
scripts/install.sh         curl | sh installer for release binaries
.github/workflows/         ci.yml, release.yml, distros.yml
```

Crate names: `qsh` on crates.io is taken by a reserved placeholder, so the library is `qsh-core` and the binaries ship in `qsh-cli`. License: MIT OR Apache-2.0.

TokenSSH's `tokenssh-link` (in the TokenSSH repository, `link/`) is where the first implementation came from: its replay buffer, QUIC endpoint sharing, pinning, pty daemon and transport race are proven on real phones. Reuse its logic, not its wire format.

## 6. Command line

```
qsh [options] [user@]host [command…]   new session (a login shell, or the command)
qsh attach host [session]              reattach a detached session
qsh ls [host]                          sessions on host (or the hosts with saved sessions)
qsh kill host session
qsh install host                       copy qsh-server to host:~/.local/bin (feature self-install)
qsh doctor [host]                      what works, what does not, the exact fix

qsh-server bootstrap | pipe            used over ssh by the client
qsh-server daemon [--foreground]       the per-user daemon (started on demand)
qsh-server status | stop
qsh-server doctor | tune [--apply|--revert]   host checks; tuning shows a diff and asks
qsh-server upgrade                     replace the running daemon in place, keeping sessions
```

- ssh's options pass through: `-p`, `-l`, `-i`, `-J`, `-F`, `-o`, `-4`, `-6`, `-v`. `--` ends options; a host named like a subcommand: `qsh -- ls`.
- Escapes after Enter, like ssh: `~.` end the session, `~d` detach (it keeps running), `~s` connection status (transport, RTT, loss, bytes), `~?` help, `~~` a literal `~`.
- Server without qsh: on a tty, one question to install it, then connect. Without a tty, exit code 42 and one line (embedders fall back to ssh).
- A detached or lost client leaves the session on the server for 6 h (1 h after its program exits). Session credentials live in `$XDG_STATE_HOME/qsh/sessions/` (0600) so `qsh attach` works after the client process died.
- Config: `~/.config/qsh/config` then `/etc/qsh/qsh_config` (TOML), `[host."pattern"]` tables (ssh-style patterns, matched against the host as typed and ssh's `HostName`), `[defaults]` and `[server]`, documented in qsh_config(5). First value wins, as in ssh_config: command line > environment > user file > system file > built-in default. Unknown keys are warnings (newer configs work with older qsh); bad values, and files others may write, are errors.
- Exit codes: the remote program's code; 255 for qsh errors (like ssh); 42 server has no qsh-server; documented in qsh(1).

## 7. Self-optimizing connections

The M2 mechanisms are specified in [m2.md](m2.md) (design and implementation plan), with their
wire formats in protocol.md.

| Mechanism | What it does | Milestone |
|---|---|---|
| Transport race | QUIC, TLS and ssh pipe with staggered starts; the first to answer the hello wins, then one ATTACH on it | M0 |
| Dead path detection | typed input unanswered and nothing received for max(2 s, 4·SRTT + 4·RTTVAR) → race the other transports in the background while keeping the connection; whichever answers first carries the session (M2). Fallback: no frame for 45 s, or input unanswered for 8 s → race again | M0, M2 |
| Network change | watch default route and addresses (netlink on Linux, route socket on macOS), migrate the QUIC connection at once | M1 |
| Path memory | per destination and network (keyed hashes; interfaces, gateways, source prefixes): remember which transport and port worked and which were blocked; start with the winner, leave out known-blocked transports and re-probe them in the background, move to a better transport when it comes back; a miss or a wrong memory falls back to the full race at once | M2 (0.3) |
| NAT keepalive learning | QUIC keep-alive starts at 20 s; when PATH_INFO shows the client's address changed without a migration while it was idle, the NAT timed out: halve it for that network (floor 5 s), grow back × 1.25 after 30 quiet minutes (ceiling 25 s); no extra application PING on idle QUIC, so a phone's radio wakes once per interval | M2 (0.3) |
| Port fallback | `extra_ports` the daemon binds where it can (443 where the administrator allows unprivileged binding), announced in the bootstrap reply; the client tries them 300 ms apart per transport and remembers the one that worked | M2 (0.3) |
| Live upgrade | a newer `qsh-server` replaces the running daemon by exec in place: sessions, programs, exit statuses, ports and keys survive; clients reconnect after GOAWAY (RESTART) | M2 (0.3) |
| Smart catch-up | the server keeps a screen model (`vt100`); when unacknowledged output exceeds 2 s of the measured delivery rate, or the user types while output is backed up, it sends the current screen (SNAPSHOT) instead of the backlog and marks the gap in scrollback. Adaptive pacing keeps about one RTT (the path's minimum, not the smoothed one) + 100 ms queued: Ctrl-C answers within 2 RTT + 100 ms plus the snapshot's transfer time | M2 (0.4) |
| Compression | zstd per message (encoder `ruzstd`, pure Rust; our own bounded decoder), independent frames ≤ 64 KiB, used when the path carries less than 4 MiB/s and the output compresses | M2 (0.4) |
| Host tuning | `qsh-server doctor` checks UDP buffers, GSO/GRO, BBR, MTU, ports, firewall (ufw, firewalld, nftables, iptables), SELinux/AppArmor, linger, runtime dir, containers, cloud provider (from DMI, no network calls) and prints the fix for this distribution; `tune --apply` applies the fixes with the distribution's tools after showing a diff, records them and `--revert`s them; `qsh doctor HOST` adds client-side probes and a diagnosis | M2 (0.5) |
| Predictive echo | like mosh: local echo, underlined until confirmed; off in full-screen programs and on fast paths | M3 |

Supported targets: Ubuntu 20.04+, Debian 11+, Fedora, RHEL/Rocky/Alma 8+, Alpine, Arch, openSUSE, Amazon Linux 2023 on x86_64, aarch64, armv7, riscv64; macOS client and server. Windows client later.

## 8. Milestones

- **M0 Foundation**: workspace, protocol specification, `qsh-core` (proto, mux, crypto, transports, session layer, server, client), `qsh` and `qsh-server` with interactive bootstrap, unit + end-to-end tests, fuzz targets, CI (fmt, clippy, test, MSRV, deny), static release builds, install script, README, security doc.
- **M1 Daily driver**: `attach` / `ls` / `kill` with saved credentials, escapes and status line, install prompt, network change watcher, config file, man pages and completions, distribution packaging, distribution-matrix end-to-end tests.
- **M2 Self-optimizing** ([m2.md](m2.md)): 0.3.0 path memory, keepalive learning, port fallback,
  daemon upgrade without losing sessions (exec in place, keeping the programs as children), chaos
  tests in CI (network namespaces, netem loss / latency / reordering, UDP block, address change,
  NAT rebinding); 0.4.0 smart catch-up and compression; 0.5.0 doctor and tune per distribution,
  `qsh doctor HOST`, and a published benchmark against ssh and mosh.
- **M3 Beyond ssh**: predictive echo, port forwarding (`-L -R -D`), `qsh cp` (resumable), agent forwarding, Homebrew.
- **M4 System service (optional)**: `qshd`, a root daemon with privilege separation that authenticates SSH keys and certificates itself on one port, for hosts where only one UDP port is open and for fleets.
- **Public 1.0** when M1 is solid and the protocol has had a review; then packaging requests to Debian, Fedora, Alpine, Arch (AUR first).
