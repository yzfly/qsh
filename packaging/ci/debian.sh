#!/bin/bash
# Build, lint, install and smoke-test the Debian packages in a Debian or Ubuntu container, as
# root (the build itself runs as an unprivileged user, like on a buildd):
#
#   docker run --rm -v "$PWD:/src" -w /src debian:13 \
#     packaging/ci/debian.sh dist/qsh-VERSION.tar.gz dist/qsh-VERSION-vendor.tar.xz out
#
# With - for the vendor tarball, it builds the way Debian itself has to: no profile, every crate
# from the archive's librust-*-dev packages (dh-cargo). It first writes out/archive-crates.txt,
# which of those the archive has at the version needed (useful on debian:testing and unstable).
# Either way the packages are then linted, installed and smoke-tested.
#
# Uses the build profile pkg.qsh.vendored (crates from the orig-vendor component tarball): the
# librust-*-dev route needs every dependency packaged at the right version, see
# packaging/README.md. Rust comes from the distribution when it is new enough (rust-version in
# Cargo.toml, 1.85: Debian 13 and later); otherwise from Ubuntu's versioned rustc-1.NN packages,
# and failing that from rustup, in which case the build skips the build-dependency check (-d)
# for rustc and cargo only.
set -euxo pipefail

src=$(realpath "$1")
vendor=$2
[ "$vendor" = - ] || vendor=$(realpath "$vendor")
out=$(realpath -m "$3")
here=$(dirname "$(realpath "$0")")
version=$(basename "$src" .tar.gz)
version=${version#qsh-}

export DEBIAN_FRONTEND=noninteractive
. /etc/os-release
# The Ubuntu image leaves man pages and docs out at install time; the smoke test needs them.
rm -f /etc/dpkg/dpkg.cfg.d/excludes
apt-get update -q
apt-get install -y -q --no-install-recommends \
	build-essential dpkg-dev fakeroot lintian man-db ca-certificates curl xz-utils
mkdir -p "$out"

# The unpacked source package, as dpkg-source -x would produce it.
useradd --create-home builder
work=/home/builder/build
mkdir -p "$work"
cp "$src" "$work/qsh_$version.orig.tar.gz"
tree="$work/qsh-$version"
tar -C "$work" -xzf "$src"
if [ "$vendor" != - ]; then
	cp "$vendor" "$work/qsh_$version.orig-vendor.tar.xz"
	mkdir "$tree/vendor"
	tar -C "$tree/vendor" --strip-components=1 -xJf "$vendor"
fi
cp -r "$tree/packaging/debian" "$tree/debian"
# The changelog's version follows Cargo.toml's (the packaging may be ahead of the last entry).
sed -i "1s/^qsh ([^)]*)/qsh ($version-1)/" "$tree/debian/changelog"

if [ "$vendor" = - ]; then
	# Every crates.io dependency of the workspace's manifests (not the path crates; dependencies
	# taken from [workspace.dependencies] are listed there) needs its librust-*-dev in
	# Build-Depends, or dh-cargo's registry lacks it and cargo stops with "no matching package".
	unlisted=$(cd "$tree" && awk '
		/^\[/ { deps = ($0 ~ /^\[(workspace\.)?(dev-|build-)?dependencies\]$/); next }
		deps && /^[A-Za-z0-9_-]+ *=/ && !/path *=/ && !/workspace *= *true/ {
			name = $1; sub(/=.*/, "", name); gsub(/_/, "-", name); print tolower(name) }
		' Cargo.toml crates/*/Cargo.toml xtask/Cargo.toml | sort -u |
		while read -r crate; do
			grep -q "^ librust-$crate-dev " debian/control || echo "$crate"
		done)
	if [ -n "$unlisted" ]; then
		for crate in $unlisted; do
			echo "::error file=packaging/debian/control::crate $crate is a dependency in Cargo.toml but librust-$crate-dev is not in Build-Depends"
		done
		exit 1
	fi
	# Which librust-*-dev Build-Depends the archive satisfies (semver: >= lower, << upper).
	sed -n 's/^ \(librust-[^ ]*\) (\([<>=]*\) \([^)]*\)).*/\1 \2 \3/p' "$tree/debian/control" |
		awk '$2 == ">=" { lo[$1] = $3; order[n++] = $1 } $2 == "<<" { hi[$1] = $3 }
			END { for (i = 0; i < n; i++) print order[i], lo[order[i]], hi[order[i]] }' |
		while read -r pkg lo hi; do
			have=$(apt-cache policy "$pkg" | sed -n 's/^ *Candidate: //p')
			if [ -z "$have" ] || [ "$have" = "(none)" ]; then
				echo "MISSING  $pkg, needs >= $lo, << $hi"
			elif ! dpkg --compare-versions "$have" ge "$lo"; then
				echo "TOO OLD  $pkg $have, needs >= $lo, << $hi"
			elif [ -n "$hi" ] && ! dpkg --compare-versions "$have" lt "$hi"; then
				echo "TOO NEW  $pkg $have, needs >= $lo, << $hi (semver-incompatible)"
			else
				echo "ok       $pkg $have"
			fi
		done | tee "$out/archive-crates.txt"
	echo "::notice title=$PRETTY_NAME librust-*-dev::$(grep -c '^ok' "$out/archive-crates.txt") of $(wc -l < "$out/archive-crates.txt") crate Build-Depends satisfied, see archive-crates.txt"
	# In unstable this can fail although every crate above is there: a crate's own dependencies
	# may be mid-transition (uninstallable until the Rust team uploads the rest); testing never
	# has such holes.
	if ! apt-get build-dep -y -q "$tree"; then
		echo "::warning title=$PRETTY_NAME librust-*-dev::the crates are in the archive but cannot be installed together (an archive transition in progress?), see apt's explanation in the log"
		exit 1
	fi
	# Source and binaries, as for an upload: lintian checks the source package too.
	build_flags=(-us -uc -sa)
	rust_path=
	rust_from="the archive (rustc $(apt-cache policy rustc | sed -n 's/^ *Installed: //p')), crates from librust-*-dev"
else
	# Rust: the archive's when new enough, else a versioned package or rustup.
	msrv=$(sed -n 's/^rust-version = "\(.*\)"/\1/p' "$tree/Cargo.toml")
	candidate=$(apt-cache policy rustc | sed -n 's/^ *Candidate: //p')
	build_flags=(-us -uc --build-profiles=pkg.qsh.vendored)
	rust_path=
	if [ -n "$candidate" ] && [ "$candidate" != "(none)" ] &&
		dpkg --compare-versions "${candidate#*:}" ge "$msrv"; then
		rust_from="the archive (rustc $candidate)"
		apt-get build-dep -y -q --build-profiles=pkg.qsh.vendored "$tree"
		# A full source + binary build: lintian checks the source package too.
		build_flags+=(-sa)
	else
		# Build-Depends without rustc and cargo, for apt-get build-dep.
		mkdir -p /tmp/bdeps/debian
		cp "$tree/debian/changelog" /tmp/bdeps/debian/
		sed -E '/^ (cargo|rustc) \(/d' "$tree/debian/control" > /tmp/bdeps/debian/control
		apt-get build-dep -y -q --build-profiles=pkg.qsh.vendored /tmp/bdeps
		versioned=$(apt-cache pkgnames rustc-1. | sed -n 's/^rustc-\(1\.[0-9]*\)$/\1/p' | sort -V | tail -n 1)
		if [ -n "$versioned" ] && dpkg --compare-versions "$versioned" ge "$msrv"; then
			apt-get install -y -q --no-install-recommends "rustc-$versioned" "cargo-$versioned"
			rust_path=/usr/lib/rust-$versioned/bin
			rust_from="the archive's versioned rustc-$versioned"
		else
			curl -sSf https://sh.rustup.rs | env RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo \
				sh -s -- -y --no-modify-path --profile minimal --default-toolchain "$msrv"
			rust_path=$(RUSTUP_HOME=/opt/rustup /opt/cargo/bin/rustc --print sysroot)/bin
			rust_from="rustup (Rust $msrv; the archive has rustc ${candidate:-none})"
		fi
		build_flags+=(-b -d)
	fi
fi
echo "::notice title=$PRETTY_NAME::Rust from $rust_from"

chown -R builder: "$work"
su builder -c "cd '$tree' && PATH='${rust_path:+$rust_path:}$PATH' dpkg-buildpackage ${build_flags[*]}"

cd "$work"
ls -l
cp -- *.deb *.ddeb *.changes *.buildinfo "$out/" 2> /dev/null || true
cp -- *.dsc *.debian.tar.* *.orig*.tar.* "$out/" 2> /dev/null || true

# lintian: every tag is reported; errors fail the job. The .changes file is left out: an
# UNRELEASED changelog is expected until the package is uploaded.
lintian_targets=(qsh-client_*.deb qsh-server_*.deb)
compgen -G "qsh_*.dsc" > /dev/null && lintian_targets+=(qsh_*.dsc)
lintian --info --display-info --pedantic --fail-on error "${lintian_targets[@]}" 2>&1 |
	tee "$out/lintian.txt"

apt-get install -y -q "./qsh-client_${version}-1_$(dpkg --print-architecture).deb" \
	"./qsh-server_${version}-1_$(dpkg --print-architecture).deb"
dpkg -L qsh-client qsh-server | tee "$out/files.txt"
for f in /usr/bin/qsh /usr/bin/qsh-server /usr/lib/systemd/user/qsh-server.service \
	/usr/share/man/man1/qsh.1.gz /usr/share/man/man1/qsh-server.1.gz \
	/usr/share/man/man5/qsh_config.5.gz \
	/usr/share/bash-completion/completions/qsh /usr/share/bash-completion/completions/qsh-server \
	/usr/share/zsh/vendor-completions/_qsh /usr/share/zsh/vendor-completions/_qsh-server \
	/usr/share/fish/vendor_completions.d/qsh.fish /usr/share/fish/vendor_completions.d/qsh-server.fish \
	/usr/share/doc/qsh-client/copyright /usr/share/doc/qsh-server/copyright; do
	test -e "$f" || { echo "missing: $f" >&2; exit 1; }
done
su builder -c "sh '$here/smoke.sh' '$version'"
