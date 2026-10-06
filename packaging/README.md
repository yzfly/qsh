# Packaging qsh

qsh aims to be a standard component of Linux distributions (docs/DESIGN.md, section 3). This
directory holds the packaging for each distribution, kept upstream so that it is built and tested
with every change and can be handed to distribution maintainers as it is.

| Directory | What | Built in CI |
|---|---|---|
| `debian/` | Debian / Ubuntu source package: `qsh-client`, `qsh-server` | Debian 13, Debian 12, Ubuntu 24.04; Debian testing and unstable with archive crates |
| `rpm/qsh.spec` | Fedora spec (Rust packaging guidelines): `qsh`, `qsh-server` | Fedora (latest); rawhide with Fedora crates |
| `alpine/APKBUILD` | aports recipe: `qsh`, `qsh-server`, `-openrc`, `-doc`, completions | Alpine (latest) |
| `arch/PKGBUILD` | AUR / Arch recipe | Arch Linux (latest) |
| `homebrew/qsh.rb` | Homebrew formula | macOS (latest) |
| `systemd/qsh-server.service` | systemd user unit, installed by every Linux package that has systemd | |
| `openrc/` | OpenRC script (per-user instances), Alpine's `qsh-server-openrc` | |
| `nfpm.yaml` | the convenience .deb/.rpm/.apk of static binaries attached to GitHub Releases | release.yml |
| `ci/` | the scripts the Packaging workflow runs, one per distribution | |
| `test/` | end-to-end tests of the static binaries on many distributions (distros.yml) | distros.yml |

All packages install the same files: `/usr/bin/qsh`, `/usr/bin/qsh-server`, the man pages qsh(1),
qsh-server(1), qsh_config(5) (`man/`), bash, zsh and fish completions (`completions/`), the
systemd user unit `/usr/lib/systemd/user/qsh-server.service` (not enabled: qsh-server starts on
demand over ssh), the licenses and the documentation. None of them enables the cargo feature
`self-install`, except Homebrew (see the formula); distribution builds make no network access at
runtime.

## How CI builds them

`.github/workflows/packaging.yml` runs on changes to `packaging/` or `Cargo.lock`, weekly, and by
hand:

1. `ci/source.sh` makes the source tarballs from the checkout: `qsh-VERSION.tar.gz` (`git archive`,
   the same layout as GitHub's tag archive the recipes download) and `qsh-VERSION-vendor.tar.xz`
   (`cargo vendor --locked --versioned-dirs`), for builders that run offline.
2. Each distribution job runs `ci/<distro>.sh` in the distribution's stock container, as root;
   the build itself runs as an unprivileged user with the distribution's own tool
   (`dpkg-buildpackage`, `rpmbuild`, `abuild`, `makepkg`, `brew`), the recipe's tests included.
3. The result is linted (`lintian`, `rpmlint`, `apkbuild-lint`, `namcap`, `brew audit --strict`),
   installed with the package manager, checked for the files above, and smoke-tested by
   `ci/smoke.sh`: versions, man pages, and a real session over the loopback (qsh bootstraps through
   a stand-in ssh, the installed qsh-server starts its daemon, the client attaches over QUIC).
4. Each job uploads the packages and lint reports as an artifact of the run.

Lint errors fail a job; warnings are reported in the artifact (`lintian.txt`, `rpmlint.txt`,
`namcap.txt`, `apkbuild-lint.txt`, `audit.txt`).

Three more jobs build the way the distributions themselves must, without the vendor tarball, and
then lint, install and smoke-test like the others: `debian:testing` and `debian:unstable` against
the archive's `librust-*-dev` through dh-cargo (report: `archive-crates.txt`), and `fedora:rawhide`
against `rust-*-devel` with `%generate_buildrequires` (report: `fedora-crates.txt`). Only
`debian:unstable` is informative (`continue-on-error`): it is where an upload is built, but some
crate of the archive is regularly uninstallable there for a few days while the Rust team uploads
a transition; testing, where britney lets only installable sets in, has to pass.

## Building locally

Make the tarballs once (needs git, cargo, xz), then run the distribution's script in its container.
Every command runs from the top of the source tree; packages land in `out/`.

```sh
packaging/ci/source.sh dist
V=$(cat dist/VERSION)
```

### Debian and Ubuntu

```sh
docker run --rm -v "$PWD:/src" -w /src debian:13 \
  packaging/ci/debian.sh dist/qsh-$V.tar.gz dist/qsh-$V-vendor.tar.xz out
```

or by hand in an unpacked source tree with `vendor/` from the vendor tarball:

```sh
cp -r packaging/debian debian
sudo apt-get build-dep -P pkg.qsh.vendored .
dpkg-buildpackage -us -uc -P pkg.qsh.vendored
```

`pkg.qsh.vendored` builds against `vendor/`; without the profile the build takes every crate from
the archive's `librust-*-dev` packages through dh-cargo, which is how a package in Debian itself
has to be built. Rust 1.85 is needed: Debian 13 has it; on Debian 12 the script uses a rustup
toolchain and `dpkg-buildpackage -d`, on Ubuntu 24.04 the archive's versioned `rustc-1.NN`
packages.

### Fedora

```sh
docker run --rm -v "$PWD:/src" -w /src fedora:latest \
  packaging/ci/fedora.sh dist/qsh-$V.tar.gz dist/qsh-$V-vendor.tar.xz out
```

or with the tarballs in `~/rpmbuild/SOURCES`:
`rpmbuild -ba --with vendor packaging/rpm/qsh.spec` (`dnf builddep -D '_with_vendor --with-vendor'`
first). Without `--with vendor` the spec follows the Fedora Rust guidelines exactly: crates from
`rust-*-devel` packages, BuildRequires generated by `%cargo_generate_buildrequires`.

### Alpine

```sh
docker run --rm -v "$PWD:/src" -w /src alpine:latest packaging/ci/alpine.sh dist/qsh-$V.tar.gz out
```

or in an aports checkout: copy `alpine/APKBUILD` to `testing/qsh/APKBUILD`, `abuild checksum`,
`abuild -r`. Like every Rust package in aports, `prepare()` runs `cargo fetch` (`options="net"`).

### Arch Linux

```sh
docker run --rm -v "$PWD:/src" -w /src archlinux:latest packaging/ci/arch.sh dist/qsh-$V.tar.gz out
```

or `makepkg -si` next to `arch/PKGBUILD`. The script also writes `.SRCINFO`.

### Homebrew

```sh
packaging/ci/homebrew.sh dist/qsh-$V.tar.gz out
```

Homebrew installs formulae only from taps: the script puts the formula, pointed at the local
tarball, into a local tap `yzfly/local`, then `brew install --build-bottle`, `brew test`,
`brew audit --strict`.

## Status and the way into each distribution

### Debian

Status: builds with `pkg.qsh.vendored` on Debian 13 (archive rustc 1.85, Build-Depends checked,
source package too), Debian 12 (rustup 1.85) and Ubuntu 24.04 (`rustc-1.91`); tests pass; lintian
`--pedantic` reports only the ITP placeholder (`wrong-bug-number-in-closes`,
`initial-upload-closes-no-bugs`) and `hardening-no-fortify-functions` (info, normal for Rust);
installs and works.

Against the archive, without `vendor/` (the `debian:testing (archive crates)` job, October 2026):
every crate is there at a version in the ranges of `debian/control` (15 of 15, e.g. clap 4.6.7,
quinn 0.11.11, rcgen 0.14.7, rustls 0.23.45, tokio 1.53.1, toml 1.1.6), and qsh 0.2.1 builds with
the plain dh-cargo route (rustc 1.95), its tests pass, lintian reports only the ITP placeholder and
the `vendor/*` paragraphs of `debian/copyright` that a build without `vendor/` does not use
(`superfluous-file-pattern`), and the installed packages pass the smoke test. No new crate
packages are needed.

In unstable the same Build-Depends are all there, but since 2026-10-04 they cannot be installed:
`rust-synstructure` 0.14.0 was uploaded that day without a 0.13 compat package, while
`librust-asn1-rs-dev` (0.7.2+ds-2) still depends on `librust-synstructure-0.13-dev`; the
archive's `librust-rcgen-dev` depends on `x509-parser` and through it on `asn1-rs` whatever
features qsh asks for (debcargo packages all of rcgen's features in one package). That is the
Rust team's transition to finish (a new `rust-asn1-rs`, or a `rust-synstructure-0.13`), not
something qsh can change: no qsh dependency version avoids it, and testing keeps the working set
until it is done.

For the archive (Debian, and from there Ubuntu):

1. Every dependency must be in the archive as `librust-*-dev` at a version that satisfies the
   semver ranges (the `>=` / `<<` pairs in `debian/control`); vendored crates are not accepted in
   Debian main. The `debian:unstable (archive crates)` job checks this on every run. A crate that
   is missing or too old is packaged with `debcargo` in the Rust team's `debcargo-conf` repository
   (salsa.debian.org/rust-team/debcargo-conf), one merge request per crate.
2. File an ITP (`reportbug wnpp`, "ITP: qsh -- remote shell over QUIC whose sessions survive
   network changes") and put its number into `debian/changelog` (`Closes: #NNNNNN`).
3. Drop the `vendor/*` paragraphs from `debian/copyright` and the vendored profile for the
   upload (or keep them for backports), set the changelog's distribution to `unstable`, build in
   a clean chroot (`sbuild`), run `lintian --pedantic` and fix what it reports. The build needs an
   installable unstable: wait for the `debian:unstable (archive crates)` job to be green (in
   October 2026 it waits for the synstructure 0.14 transition, see above).
4. Find a sponsor (the Debian Rust team, or debian-mentors through mentors.debian.net), since the
   maintainer is not a Debian Developer. Ubuntu picks the package up from Debian unstable.

### Fedora

Status: builds with `--with vendor` on Fedora (latest, 44), tests pass, rpmlint: 0 errors,
0 warnings; bundled `Provides: bundled(crate(...))` generated from `cargo-vendor.txt`; installs
and works.

Against Fedora's crates (the `fedora:rawhide (Fedora crates)` job, October 2026) everything is
packaged: all 42 generated `crate(...)` BuildRequires resolve (e.g. clap 4.6.7, quinn 0.11.12,
rcgen 0.14.5, zeroize 1.9.0), and qsh 0.2.1 builds without `--with vendor`, its tests pass,
rpmlint reports 0 errors and 0 warnings, and the installed packages pass the smoke test. The
crates have to be installed with their documentation (Koji and mock do; the container image's
`tsflags=nodocs` does not): `rust-*-devel` marks a crate's `README.md` `%doc`, and crates such as
zeroize compile it in.

For Fedora:

1. The `fedora:rawhide (Fedora crates)` job builds without `--with vendor`. A crate that is
   missing (after a future dependency change) gets a `rust-CRATE` package: generate
   it with `rust2rpm CRATE`, submit a review request in Red Hat Bugzilla (product Fedora,
   component Package Review).
2. Then qsh itself: a review request for `qsh` with this spec built without `--with vendor`
   (vendored builds are allowed in Fedora only by exception, e.g. for EPEL; the spec supports
   both). The license tag must be regenerated from `%{cargo_license_summary}` on every update;
   against Fedora's crates it lists only what is linked in, so the tag for the submission drops
   `Unicode-3.0` (unicode-ident, build time only) that the vendored summary has, and Fedora's
   ring is `Apache-2.0 AND ISC AND (MIT OR Apache-2.0)` (the summary is in the rawhide job's log).
3. After approval: `fedpkg request-repo qsh`, import, build for rawhide and branched releases,
   Bodhi updates. EPEL 10 can use `--with vendor`.

### Alpine

Status: builds on Alpine (latest) with `abuild`, tests pass (one skipped, see `check()`: it
assumes a faster `yes` than busybox's), `apkbuild-lint` clean, installs and works.

For aports: a merge request on gitlab.alpinelinux.org/alpine/aports adding `testing/qsh/APKBUILD`
(with the init script it installs from the tarball), after `abuild checksum`, `apkbuild-lint` and
a build on all architectures in CI there. A package moves from testing to community once it has
been stable and maintained for a while (a further MR that moves it).

### Arch Linux

Status: builds on Arch (latest) with `makepkg` (`!lto`: makepkg's LTO flags make ring's C objects
unreadable to rustc's lld), tests pass, namcap clean, installs and works; the `-debug` package
carries the symbols.

For the AUR: clone `ssh://aur@aur.archlinux.org/qsh.git` (an AUR account with an ssh key), copy
`arch/PKGBUILD`, `updpkgsums`, `makepkg --printsrcinfo > .SRCINFO`, commit both and push. Every
version bump: pkgver, pkgrel=1, `updpkgsums`, regenerate `.SRCINFO` (the CI artifact contains the
`.SRCINFO` for the built version). Popular AUR packages can be adopted into `extra` by an Arch
package maintainer; nothing to file for that.

### Homebrew

Status: the formula builds from source (a bottle is the artifact), `brew test` (a real loopback
session) passes and `brew audit --strict` is clean on macOS (latest, arm64).

1. A tap first: repository `yzfly/homebrew-tap` with `Formula/qsh.rb`; users run
   `brew install yzfly/tap/qsh`. Bottles can be built there with `brew test-bot`.
2. homebrew-core requires notability for a self-submitted formula (roughly 75 stars, 30 forks or
   30 watchers on GitHub, a stable tagged release, and not being only the author's project),
   `brew audit --new --strict --online qsh` clean, and a test that does more than `--version`
   (this formula's test runs a session). Then a pull request to Homebrew/homebrew-core adding
   `Formula/q/qsh.rb`; afterwards BrewTestBot bumps it on new tags via livecheck.
