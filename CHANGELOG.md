# Changelog

All notable changes to qsh are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and qsh adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a minor version may
contain incompatible changes; they are listed under **Changed** with what to do.

The release workflow publishes the section of a version as its release notes, so every release
needs a section `## [X.Y.Z] - YYYY-MM-DD` here before its tag is pushed.

## [Unreleased]

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

[Unreleased]: https://github.com/yzfly/qsh/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/yzfly/qsh/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/yzfly/qsh/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/yzfly/qsh/releases/tag/v0.1.0
