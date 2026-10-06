#!/bin/sh
# Source tarballs for the distribution builds, from a git checkout (run in its top directory):
#
#   packaging/ci/source.sh [OUTDIR]        # default: dist
#
# OUTDIR/qsh-VERSION.tar.gz          `git archive` of HEAD, prefix qsh-VERSION/: the same layout
#                                    as GitHub's tag archive, which the recipes' Source0 points at
# OUTDIR/qsh-VERSION-vendor.tar.xz   `cargo vendor --locked --versioned-dirs`, prefix vendor/: every crate in
#                                    Cargo.lock, for builders that run offline (Debian's
#                                    pkg.qsh.vendored profile, Fedora's --with vendor)
# OUTDIR/VERSION                     the workspace version from Cargo.toml
#
# Needs git, cargo, tar and xz. The tarballs are reproducible for a given commit.
set -eu

out=${1:-dist}
version=$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml)
[ -n "$version" ] || { echo "source.sh: no version in Cargo.toml" >&2; exit 1; }
epoch=$(git log -1 --format=%ct)

mkdir -p "$out"
git archive --format=tar --prefix="qsh-$version/" HEAD | gzip -9n > "$out/qsh-$version.tar.gz"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cargo vendor --locked --versioned-dirs --quiet "$tmp/vendor" > /dev/null
tar -C "$tmp" --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
	-cf - vendor | xz -T1 -9 > "$out/qsh-$version-vendor.tar.xz"

echo "$version" > "$out/VERSION"
ls -l "$out"
