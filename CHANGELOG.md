# Changelog

All notable changes to qsh are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and qsh adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a minor version may
contain incompatible changes; they are listed under **Changed** with what to do.

The release workflow publishes the section of a version as its release notes, so every release
needs a section `## [X.Y.Z] - YYYY-MM-DD` here before its tag is pushed.

## [Unreleased]

## [0.5.0] - 2026-10-07

Connections that optimize themselves (milestone M2). 0.3.0 and 0.4.0 were development
milestones and were not released; their changes are listed here.

### Added

- Smart catch-up: when output floods a slow link, the server stops streaming the backlog and
  sends the current screen instead (a SNAPSHOT, built from a model of the terminal), marking
  the skipped output in scrollback. Ctrl-C during `cat bigfile` on a 270 ms link takes effect
  in about half a second instead of tens of seconds. A new client process attaching to a
  session gets the recent scrollback and then the current screen.
- Compression: on a slow path the server compresses output with zstd (decoded by a bounded
  decoder of our own); a 1.5 MB build log over 300 kB/s takes 0.4 s instead of 5 s.
- Path memory: per network, qsh remembers which transport and port worked and starts with it
  at once; a transport that is blocked there is skipped, then re-probed in the background
  (1 min up to 24 h). When a better transport comes back, sessions move to it without a
  visible reconnect. Stored as salted hashes in `$XDG_STATE_HOME/qsh/paths.json` (`path_memory`
  in qsh_config(5)).
- NAT keepalive learning: when the server sees the client's address change on an idle
  connection, the NAT forgot it; the keepalive interval for that network halves (down to 5 s)
  and slowly grows back. Idle QUIC connections otherwise send nothing, which spares phone
  radios. `keepalive = "auto"` or a number of seconds.
- Extra ports: `extra_ports` in the `[server]` table; the daemon binds each it can on UDP and
  TCP and announces them; clients try them when the first port is blocked.
- In-place daemon upgrade: when a newer `qsh-server` reaches the daemon (or on
  `qsh-server upgrade`, or by itself when idle), it executes the new version in its own
  process: same process id, same ports, every session and its programs kept; clients reconnect
  within about a second. If the new version cannot take over, the old one carries on and that
  program is not tried again automatically. The systemd unit reloads with `qsh-server upgrade`.
- `qsh-server doctor` checks what matters for qsh on this host (ports and firewall: ufw,
  firewalld, nftables, iptables; UDP buffers, GSO/GRO, BBR, IPv6, MTU, linger, the runtime
  directory, SELinux and AppArmor, the clock, limits, conntrack, cloud and container) and
  prints the exact fix for this distribution. `qsh doctor HOST` adds what the client sees:
  which transports work from here, RTT, loss, MTU, NAT. `--json` for scripts.
- `qsh-server tune` shows what it would change (sysctl.d, modules-load.d, the firewall,
  linger), and with `--apply` (as root, after asking) changes it; `--revert` puts every file
  back byte for byte, with its mode and owner. A firewalld service and a ufw application
  profile ship with the packages.
- Release signatures: `SHA256SUMS` is signed (minisign, Ed25519). `qsh install` and the install
  script verify it; the public key is in docs/security.md.
- The daemon asks for 4 MiB UDP buffers and uses BBR for TLS over TCP where the kernel has it.

### Changed

- Release builds unwind on panic: a fault in the screen model or the codec turns that feature
  off for one session; it never takes down the daemon or other sessions.
- `qsh-server status` reports ports, extra ports, sessions and upgrade state.
- The offer to install `qsh-server` on a host now defaults to no.
- Text from the server (errors, `qsh ls`, doctor reports) is shown with control characters and
  escape sequences removed.

### Fixed

- A command moving much data both ways (`qsh host -- cat < big > out`) could stall forever on a
  fast network: the server stopped reading the stream while the program's input queue was
  full, so the acknowledgements that would let the program write (and then read) waited behind
  input. The server now always reads the stream and holds input it cannot take yet (up to
  4 MiB); output keeps flowing during a large paste into a terminal session too.
- After UDP was blocked during a session, a new `qsh attach` still tried QUIC first: the
  failure is now recorded when TLS wins the race, and the last winner breaks ties.
- `qsh install` no longer falls back to plain http, and it checks the release signature.

### Security

- Output a program prints can no longer exhaust the daemon's memory or CPU through the screen
  model: string sequences (OSC, DCS, APC, ...) never reach it, repeat counts are clamped to
  the screen, and each model has a work budget.
- The program an upgrade runs is opened once, checked through that descriptor (including every
  directory above it) and executed by descriptor.
- `qsh-server tune --revert` accepts only a root-owned, private record of changes `tune`
  itself makes.

## [0.2.1] - 2026-10-06

### Fixed

- `qsh --help`, the man pages and zsh completions showed literal backticks around `[user@]host`.
- Tests no longer depend on the machine's speed (distribution builders run them on slow and
  emulated machines): deadlines instead of fixed sleeps, a time scale for every wait
  (`QSH_TEST_TIME_SCALE`), large outputs without relying on a fast `yes`, the daemon's real
  readiness. The ticker used by tests traps SIGINT, as bash may otherwise ignore a ^C that
  arrives while a child exits.

### Changed

- rcgen 0.14 and clap_mangen 0.3, the versions Debian and Fedora package; certificates are
  unchanged.

## [0.2.0] - 2026-10-06

### Added

- `qsh attach HOST [SESSION]`: back into a session after `~d`, a closed laptop or a killed
  client, with the recent output replayed. Saved credentials make it direct, without ssh; when
  they are stale, qsh asks the host again over ssh.
- `qsh ls [HOST]` (`--json`) and `qsh kill HOST SESSION|--all`.
- `qsh install HOST`, and on a terminal an offer to install `qsh-server` the first time a host
  does not have it: a local copy when it fits, else the release download checked against
  `SHA256SUMS`, else the install script on the host. The new binary must run before it replaces
  anything. (Cargo feature `self-install`, on in release binaries and Homebrew.)
- Configuration files `/etc/qsh/qsh_config` and `~/.config/qsh/config` (qsh_config(5)): per-host
  transports, ssh program and options, escape character, install prompt, and a `[server]` table.
- Network changes are noticed at once (netlink on Linux, the routing socket on macOS): the QUIC
  connection moves to the new path and is probed; a dead path is replaced within seconds.
- A connection notice on the bottom line in full-screen programs, removed when the connection is
  back; `~s` shows every transport's outcome.

### Changed

- A tty session keeps acknowledged output as scrollback up to its 8 MiB buffer, so a new client
  process attaching sees the recent output.

## [0.1.1] - 2026-10-06

### Fixed

- When a host has no `qsh-server`, qsh printed `run: qsh install HOST`, a command that comes
  only in M1. It now prints a command that works today:
  `ssh HOST 'curl -fsSL https://github.com/yzfly/qsh/releases/latest/download/install.sh | sh -s -- --server-only'`.
  The install script and the READMEs say the same.

## [0.1.0] - 2026-10-06

The first preview. The protocol and command line may still change before 1.0.

### Added

- `qsh [user@]host [command]`: log in with your own ssh (keys, agent, `~/.ssh/config`,
  ProxyJump, passwords and 2FA), then continue the session over QUIC. The session survives
  network changes and sleep; after a reconnect both sides resend what the other missed.
- Three transports raced on every connect: QUIC, TLS 1.3 over TCP, and a pipe through ssh, so
  qsh works where UDP or the daemon's ports are blocked.
- Escapes after Enter: `~.` end, `~d` detach, `~s` connection status, `~?` help, `~~` a `~`.
- Commands without a terminal are byte exact like ssh: stdout and stderr apart, end of input
  delivered, the remote exit status returned.
- `qsh-server`: a per-user daemon started on demand over ssh, no root and no configuration; the
  first free port of 60443-60542 on UDP and TCP; `status`, `stop`, a systemd user unit.
- Security: the daemon certificate is pinned through ssh, attach proofs are bound to the
  connection with the TLS exporter and are mutual, session keys rotate on every attach, limits
  and QUIC Retry before authentication, control sockets checked both ways.
- The qsh/1 protocol specification (`docs/protocol.md`), security model (`docs/security.md`) and
  design (`docs/DESIGN.md`).
- `qsh-core`, the library behind both programs, for embedding.
- Static binaries for Linux (x86_64, aarch64, armv7, riscv64) and macOS, `.deb`, `.rpm` and
  `.apk` packages, an install script, man pages and shell completions.
- Tested end to end against a real sshd on Ubuntu 20.04 and 24.04, Debian 12, Fedora, Rocky
  Linux 9, Alpine, Arch, openSUSE Tumbleweed and Amazon Linux 2023, with UDP blocked and with
  only ssh reachable.

[Unreleased]: https://github.com/yzfly/qsh/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/yzfly/qsh/compare/v0.2.1...v0.5.0
[0.2.1]: https://github.com/yzfly/qsh/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/yzfly/qsh/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/yzfly/qsh/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/yzfly/qsh/releases/tag/v0.1.0
