# Contributing to qsh

Thank you for helping. qsh aims to become a standard Linux component, installed next to openssh,
so the bar for changes is that of security-sensitive system software: small, reviewed, tested and
documented. This page tells you how to meet it without guessing.

## Before you start

- **Read [docs/DESIGN.md](docs/DESIGN.md).** It is the contract. A change of behavior, of the
  protocol or of a public interface starts as a change to the design (or to
  [docs/protocol.md](docs/protocol.md) / [docs/security.md](docs/security.md)), discussed in an
  issue or in the pull request that implements it.
- **Security issues** go through [SECURITY.md](SECURITY.md), never a public issue.
- For anything larger than a bug fix, open an issue first so we can agree on the approach.

## Building and testing

You need Rust (the MSRV is the `rust-version` in [Cargo.toml](Cargo.toml), currently 1.85) and a C
compiler for `ring`. No other system libraries.

```sh
cargo build                                  # debug build of qsh and qsh-server
cargo test --workspace                       # unit, property and end-to-end tests
cargo test --workspace --all-features        # the same with self-install
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
cargo doc --workspace --no-deps              # must build without warnings
cargo deny check                             # licenses, advisories, duplicate and banned crates
```

CI runs all of these on Linux and macOS, plus the tests with the MSRV toolchain:

```sh
cargo +1.85 test --workspace --locked
```

End-to-end tests in `crates/qsh-cli/tests/` run real `qsh` and `qsh-server` processes against a
fake `ssh`; they need no network and no sshd. Tests must use their own temporary directories,
ports and `XDG_*` directories, and must never touch your real `~/.config/qsh` or kill processes
they did not start.

The distribution matrix (`.github/workflows/distros.yml`) runs qsh against sshd on nine Linux
distributions in containers; to run one locally with docker:

```sh
cargo build --release --target x86_64-unknown-linux-musl -p qsh-cli --bins
QSH_BIN_DIR=target/x86_64-unknown-linux-musl/release packaging/test/e2e.sh debian:12
```

### Fuzzing

Every parser has a [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) target in `fuzz/`, which
needs a nightly toolchain:

```sh
cargo install cargo-fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run <target> -- -max_total_time=300
```

CI fuzzes each target for a minute on every change. A new parser, or a new message type, comes
with a fuzz target or an extension of an existing one. Crashes found by fuzzing are fixed with the
crashing input added as a regression test.

### Man pages and completions

`man/` and `completions/` are generated from the command-line definitions and committed, so that
distributions can package them without running our binaries. After changing options or help
text, regenerate them (`cargo xtask gen`) and commit the result; CI fails when they are stale.

## Code rules

- `#![forbid(unsafe_code)]` everywhere except `qsh-core/src/sys.rs` (pty, termios, file
  descriptors). Every `unsafe` block there has a `// SAFETY:` comment saying why it is sound.
- New dependencies need a reason in the pull request. Prefer crates already packaged by Debian and
  Fedora, keep default features off, and never add a build-time download or bundled C code.
  `cargo deny check` must pass.
- No network access at runtime other than the protocol itself; anything that downloads is behind
  the `self-install` feature.
- Paths follow FHS and XDG (DESIGN.md section 3). Errors are one line saying what happened and
  what to do.
- Public items of `qsh-core` are documented. After 1.0 its API follows semver.
- The session layer has property tests; keep them passing and extend them with the code.

## Commits and pull requests

- One logical change per commit, and the tree builds and passes tests at every commit.
- Commit messages: a subject in the imperative mood of at most about 72 characters, a blank line,
  then a body that explains why when it is not obvious. Reference issues as `Fixes #123`.

  ```
  session: resend from the peer's acknowledged offset after resume

  The client resent from its own last-sent offset, duplicating output when an
  ACK had been lost with the connection.

  Fixes #42
  ```

- Add an entry under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md) for anything a user,
  packager or embedder would notice.
- No Developer Certificate of Origin or contributor license agreement is required: you keep the
  copyright to your contributions, and the license clause below applies.

## Packaging

The files in `packaging/` are maintained here so distributions can start from them. If you
package qsh for a distribution, we would like to hear from you, and patches that make the build
easier for you (feature flags, paths, generated files) are welcome.

## License

qsh is licensed under either of the [Apache License, Version 2.0](LICENSE-APACHE) or the
[MIT license](LICENSE-MIT), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
qsh by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
