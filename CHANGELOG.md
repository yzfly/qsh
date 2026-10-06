# Changelog

All notable changes to qsh are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and qsh adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a minor version may
contain incompatible changes; they are listed under **Changed** with what to do.

The release workflow publishes the section of a version as its release notes, so every release
needs a section `## [X.Y.Z] - YYYY-MM-DD` here before its tag is pushed.

## [Unreleased]

### Added

- Design document (`docs/DESIGN.md`): architecture, the standard-component bar, command line,
  self-optimizing connections and milestones.
- The qsh/1 protocol specification (`docs/protocol.md`) and security model (`docs/security.md`).
- Workspace with the `qsh-core` library and the `qsh-cli` package (`qsh` and `qsh-server`).
- Install script for release binaries (`scripts/install.sh`), with checksum verification.
- CI (format, lints, tests on Linux and macOS, MSRV, `cargo deny`, fuzzing, docs), release builds
  of static binaries for six targets with provenance attestations, and end-to-end tests on nine
  Linux distributions.
- Packaging for Debian, RPM, Alpine, Arch and Homebrew, a systemd user unit and an OpenRC script.

[Unreleased]: https://github.com/yzfly/qsh/commits/main
