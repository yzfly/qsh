# qsh

**A remote shell over QUIC. If you can `ssh host`, you can `qsh host` — and it never drops.**

[![CI](https://github.com/yzfly/qsh/actions/workflows/ci.yml/badge.svg)](https://github.com/yzfly/qsh/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

English | [简体中文](README.zh-CN.md)

qsh logs in with the ssh you already have — the same hosts, `~/.ssh/config`, keys, agent,
`known_hosts`, ProxyJump, passwords and 2FA — and then moves your session onto QUIC. The session
lives on the server; the network connection is a replaceable pipe. Switch from Wi-Fi to
cellular, close the laptop for the night, ride a train through tunnels: the shell is still there,
with every byte of output you missed.

> **Status: pre-1.0, under active development.** The protocol and command line may still change
> before 1.0. See [the milestones](docs/DESIGN.md#8-milestones) for what is being built now.

```console
$ qsh build-box
build-box:~$ cargo build --release      # close the lid, change networks, open it again
   Compiling ...                        # the output you missed is replayed, then it continues
```

## Why qsh

|                              | ssh   | mosh                              | Eternal Terminal | **qsh** |
| ---------------------------- | ----- | --------------------------------- | ---------------- | ------- |
| Wi-Fi ↔ cellular, IP changes | drops | survives                          | survives         | survives (QUIC connection migration) |
| Laptop asleep for hours      | drops | survives                          | survives         | survives, and **replays the output you missed** |
| Scrollback                   | yes   | **no** (screen sync only)         | yes              | yes, byte exact |
| UDP blocked                  | works | **fails**                         | works (TCP)      | races QUIC, TLS over TCP and an ssh pipe; uses whichever works |
| Typing on a 300 ms link      | laggy | predictive echo                   | laggy            | predictive echo *(planned, M3)* |
| Flood of output, then Ctrl-C | slow  | instant                           | slow             | instant: smart catch-up *(planned, M2)* |
| Port forwarding, file copy   | yes   | no                                | forwarding       | over QUIC streams *(planned, M3)* |
| Server setup                 | sshd  | mosh-server, UDP 60000–61000 open | etserver as root | `qsh-server`: no root, no config; `qsh` offers to install it |
| Maintained                   | yes   | last release 2022                 | slow             | yes |

What qsh does not do: it does not replace sshd or your authentication. Every session starts with
an ordinary ssh login, so qsh never asks you to trust anything ssh does not already trust.

## Install

**Release binaries** (Linux x86_64 / aarch64 / armv7 / riscv64, static; macOS x86_64 / arm64):

```sh
curl -fsSL https://github.com/yzfly/qsh/releases/latest/download/install.sh | sh
```

The script picks the build for your system, checks it against the release's `SHA256SUMS` and
installs `qsh` and `qsh-server` into `~/.local/bin` (`/usr/local/bin` as root). Options:
`--version 0.1.0`, `--prefix DIR`, `--server-only` (just `qsh-server`, for servers). Prefer to
read it first? It is [scripts/install.sh](scripts/install.sh).

**From source** with Rust 1.85 or later:

```sh
cargo install --locked qsh-cli                          # qsh and qsh-server
cargo install --locked qsh-cli --features self-install  # plus `qsh install HOST`
```

**Packages**: `.deb`, `.rpm` and `.apk` packages are attached to every
[release](https://github.com/yzfly/qsh/releases). Native packages for Debian, Fedora, Alpine,
Arch (AUR) and Homebrew are coming; the packaging lives in [packaging/](packaging/).
Each of those recipes is built from source with the distribution's own tools, installed and
smoke-tested in CI ([Packaging](https://github.com/yzfly/qsh/actions/workflows/packaging.yml));
see [packaging/README.md](packaging/README.md) for local builds and the road into each distribution.

<details>
<summary>Verifying a download</summary>

Every release asset has a checksum in `SHA256SUMS` and a build provenance attestation signed
through Sigstore by the GitHub Actions run that built it:

```sh
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify qsh-0.1.0-x86_64-unknown-linux-musl.tar.gz --repo yzfly/qsh
```

</details>

## Quick start

```sh
qsh myserver                    # a login shell, like ssh myserver
qsh -p 2222 alice@10.0.0.5      # ssh's options work: -p -l -i -J -F -o -4 -6 -v
qsh myserver -- htop            # run a command in a session
```

The server needs `qsh-server`, nothing else: no root, no daemon to enable, no config file. Install
it into `~/.local/bin` on the host with the same script:

```sh
ssh myserver 'curl -fsSL https://github.com/yzfly/qsh/releases/latest/download/install.sh | sh -s -- --server-only'
```

Or let qsh do it: the first time you connect to a host without `qsh-server`, qsh asks once
whether to install it, then connects; `qsh install myserver` does it on its own. qsh looks at the
host's system over ssh, then copies its own `qsh-server` when it was built for that system, or
downloads the matching release archive on your machine, checks it against the release's
`SHA256SUMS` and copies it over, so the host needs no internet access. Builds without the
`self-install` feature (distribution packages) never download anything: they print the command
above instead.

qsh listens on the first free UDP and TCP port from 60443–60542 on the server. If a firewall
blocks them, qsh still works: it falls back to TLS over TCP, then to a pipe through ssh itself.
`qsh doctor myserver` *(planned, M2)* tells you which transports work and what to open for the
fastest one.

### Sessions outlive the client

```sh
qsh myserver            # ... then type  ~d  to detach; the session keeps running
qsh ls                  # the sessions saved on this machine, every host (no network)
qsh ls myserver         # the sessions on myserver: id, name, state, kind, age, command
qsh attach myserver     # back in, with the output produced while you were away
qsh attach myserver 3f2a  # a given session: its id, a unique prefix of it, or its name
qsh kill myserver 3f2a  # end a session (--all: every session there)
```

```
$ qsh ls myserver
ID        NAME  STATE     KIND  CREATED    COMMAND
3f2a9c1e  -     detached  tty   2 h ago    make -j8
77c0d1aa  -     attached  tty   5 min ago  (login shell)
```

The credentials of each session are saved in `$XDG_STATE_HOME/qsh/sessions/` (mode 0600), so
`qsh attach` goes straight to the server, without ssh, even after your laptop rebooted or the
client was killed. If they are no longer valid, qsh gets new ones over ssh. With several
detached sessions and none named, qsh asks which (or, in a script, lists them and fails);
`qsh ls --json` is for scripts.

A detached or disconnected session is kept for 6 hours (1 hour after its program exits).

When the connection is lost for more than 3 seconds, qsh says so on one line: in a full-screen
program (vim, htop) on the bottom line, drawn over the screen and removed, with a full repaint,
when the connection is back; in a shell as an ordinary line. qsh notices network changes
(netlink on Linux, the routing socket on macOS) and moves the connection at once.

### Escapes

At the start of a line, like ssh:

| Keys | Action |
| ---- | ------ |
| `~.` | end the session |
| `~d` | detach (the session keeps running on the server) |
| `~s` | connection status: transport, round-trip time, bytes, time attached, how each transport fared |
| `~?` | list the escapes |
| `~~` | send a literal `~` |

### Exit status

The remote program's exit status; 255 when qsh itself fails (like ssh); 42 when the host has no
`qsh-server` and qsh is not on a terminal to offer to install it, so scripts can fall back to
ssh.

## How it works

1. `qsh host` runs your ssh, as is, with the remote command `qsh-server bootstrap`. Password and
   2FA prompts work as usual.
2. On the server, `qsh-server` starts (or finds) your per-user daemon, which opens a session and
   replies with a session key, its ports and the SHA-256 of its certificate. The ssh connection
   closes.
3. The client connects to the daemon over QUIC, TLS over TCP and the ssh pipe at once, with
   staggered starts, and keeps the first that authenticates. It pins the certificate it was told
   about over ssh and proves the session key bound to that very connection.
4. Both sides number every byte of the terminal stream. After any break, the client reconnects —
   no ssh needed — and both resend from what the other last received.

The details: [docs/DESIGN.md](docs/DESIGN.md) (architecture and decisions),
[docs/protocol.md](docs/protocol.md) (the qsh/1 wire protocol, a specification others can
implement), [docs/security.md](docs/security.md) (threat model and authentication).

## Configuration

None is needed. qsh reads your ssh configuration through ssh itself. Its own settings, if you
want any, are TOML: `/etc/qsh/qsh_config` for the system, then `~/.config/qsh/config`, with
`[defaults]` and `[host."pattern"]` tables. The reference is `man qsh_config` (qsh_config(5)).

Paths follow the XDG base directories: configuration in `$XDG_CONFIG_HOME/qsh/`, saved session
credentials (mode 0600) in `$XDG_STATE_HOME/qsh/`, sockets in `$XDG_RUNTIME_DIR/qsh/`.

## Security

Trust is anchored in ssh: no new keys to distribute, no new long-lived secret, no listener that
accepts anything before authentication, and nothing runs as root. `qsh-server` runs as you.
Read [docs/security.md](docs/security.md) for the model, and [SECURITY.md](SECURITY.md) to report
a vulnerability privately.

## Platforms

Ubuntu 20.04+, Debian 11+, Fedora, RHEL / Rocky / Alma 8+, Alpine, Arch, openSUSE and Amazon
Linux 2023 on x86_64, aarch64, armv7 and riscv64; macOS as client and server. Windows client
later. CI runs qsh end to end against each of these distributions, including with UDP blocked.

## Embedding

The protocol, transports and session layer are a library, [`qsh-core`](crates/qsh-core), with a
semver-stable API from 1.0. TokenSSH, a phone app for controlling servers, is its first embedder.

## Contributing

Bug reports, reviews of the protocol and security model, and packaging help are especially
welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
qsh by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
