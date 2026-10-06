#!/bin/sh
# Install qsh from its GitHub release binaries.
#
#   curl -fsSL https://github.com/yzfly/qsh/releases/latest/download/install.sh | sh
#   curl -fsSL https://github.com/yzfly/qsh/releases/latest/download/install.sh | sh -s -- --server-only
#
# Options (each has an environment variable, the option wins):
#   --version VERSION   install this release, e.g. 0.1.0 (QSH_VERSION; default: the latest release)
#   --prefix DIR        install into DIR/bin, DIR/share/man, ... (QSH_PREFIX; default: ~/.local,
#                       or /usr/local when run as root)
#   --server-only       install only qsh-server (QSH_SERVER_ONLY=1); what `qsh install HOST` uses
#   --require-signature refuse to install when the signature cannot be checked here
#                       (QSH_REQUIRE_SIGNATURE=1); what `qsh install HOST` uses
#   -h, --help          show this help
# QSH_DOWNLOAD_URL overrides https://github.com/yzfly/qsh/releases (mirrors, tests); only
# https:// is downloaded, redirects included.
#
# The download is checked against the release's SHA256SUMS before anything is installed, and
# SHA256SUMS against its signature (SHA256SUMS.minisig) by the qsh release key below, with
# minisign or OpenSSL 3 when either is installed; without them the script says so and relies
# on https alone, unless --require-signature. Check by hand with:
#   minisign -Vm SHA256SUMS -P RWTYvXVs30N3JIE/A5TMPWUWD9ktnPZqQ6lSzYJahI7u5lpiPBCKWHlf
# Supported: Linux (x86_64, aarch64, armv7, riscv64; static musl binaries) and macOS (x86_64, arm64).
#
# Everything happens inside main(), called on the last line, so a truncated download runs nothing.

set -eu

QSH_REPO_URL="https://github.com/yzfly/qsh/releases"

# The qsh release key (minisign, key id 247743DF6C75BDD8), as in docs/security.md
QSH_RELEASE_KEY="RWTYvXVs30N3JIE/A5TMPWUWD9ktnPZqQ6lSzYJahI7u5lpiPBCKWHlf"

say() {
    printf 'qsh-install: %s\n' "$*" >&2
}

die() {
    printf 'qsh-install: error: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
usage: install.sh [--version VERSION] [--prefix DIR] [--server-only] [--require-signature]

Install qsh and qsh-server from the GitHub release binaries.

  --version VERSION   the release to install, e.g. 0.1.0 (QSH_VERSION; default: latest)
  --prefix DIR        install into DIR/bin (QSH_PREFIX; default: ~/.local, /usr/local as root)
  --server-only       install only qsh-server (QSH_SERVER_ONLY=1)
  --require-signature refuse to install when the release signature cannot be checked
                      (needs minisign or OpenSSL 3; QSH_REQUIRE_SIGNATURE=1)
  -h, --help          show this help
EOF
}

has() {
    command -v "$1" >/dev/null 2>&1
}

# download URL FILE: https only, redirects included (curl is told; wget's redirects are read
# from its headers, and a download that went through anything but https is thrown away)
download() {
    if has curl; then
        curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL --retry 3 -o "$2" "$1"
    elif has wget; then
        case "$1" in https://*) ;; *) die "only https:// downloads: $1" ;; esac
        wget -nv -S --https-only --max-redirect=10 -O "$2" "$1" 2>"$2.headers" || return 1
        if grep -i 'location:' "$2.headers" | grep -iv 'location: *https://' | grep -q '://'; then
            rm -f "$2" "$2.headers"
            die "the download of $1 was redirected to plain http"
        fi
        rm -f "$2.headers"
    else
        die "neither curl nor wget is installed"
    fi
}

# b64d: base64 on stdin, decoded
b64d() {
    if has openssl; then
        openssl base64 -d -A
    else
        base64 -d
    fi
}

# verify_openssl SUMS MINISIG DIR: the minisign signature, with OpenSSL 3 (Ed25519, BLAKE2b)
verify_openssl() {
    v=$3/v
    mkdir "$v"
    printf '%s' "$QSH_RELEASE_KEY" | b64d > "$v/pk" || return 1
    sed -n 2p "$2" | tr -d '\r' | b64d > "$v/sig" || return 1
    sed -n 4p "$2" | tr -d '\r' | b64d > "$v/global" || return 1
    [ "$(wc -c < "$v/pk" | tr -d ' ')" = 42 ] && [ "$(wc -c < "$v/sig" | tr -d ' ')" = 74 ] &&
        [ "$(wc -c < "$v/global" | tr -d ' ')" = 64 ] || return 1
    # The same key id
    [ "$(dd if="$v/pk" bs=1 skip=2 count=8 2>/dev/null | od -An -tx1)" = \
        "$(dd if="$v/sig" bs=1 skip=2 count=8 2>/dev/null | od -An -tx1)" ] || return 1
    # An Ed25519 public key as DER: the SubjectPublicKeyInfo header, then the key
    { printf '\060\052\060\005\006\003\053\145\160\003\041\000'; tail -c 32 "$v/pk"; } > "$v/pk.der"
    openssl pkey -pubin -inform DER -in "$v/pk.der" -out "$v/pk.pem" 2>/dev/null || return 1
    tail -c 64 "$v/sig" > "$v/s"
    case "$(head -c 2 "$v/sig")" in
        ED) openssl dgst -blake2b512 -binary "$1" > "$v/m" || return 1 ;;
        Ed) cp "$1" "$v/m" ;;
        *) return 1 ;;
    esac
    openssl pkeyutl -verify -pubin -inkey "$v/pk.pem" -rawin -in "$v/m" -sigfile "$v/s" >/dev/null 2>&1 || return 1
    { cat "$v/s"; sed -n 3p "$2" | tr -d '\r' | sed 's/^trusted comment: //' | tr -d '\n'; } > "$v/c"
    openssl pkeyutl -verify -pubin -inkey "$v/pk.pem" -rawin -in "$v/c" -sigfile "$v/global" >/dev/null 2>&1
}

# verify_signature SUMS MINISIG DIR VERSION: the release key's signature of SUMS, for VERSION
# (its trusted comment); dies when it does not check out. Returns 1 when nothing here can
# check it.
verify_signature() {
    if has minisign; then
        minisign -Vqm "$1" -x "$2" -P "$QSH_RELEASE_KEY" >/dev/null ||
            die "SHA256SUMS is not signed by the qsh release key; not installing"
    elif has openssl && openssl version 2>/dev/null | grep -q '^OpenSSL [3-9]'; then
        verify_openssl "$1" "$2" "$3" ||
            die "SHA256SUMS is not signed by the qsh release key; not installing"
    else
        return 1
    fi
    # Checked above: the trusted comment is the signer's; it names the version
    [ "$(sed -n 3p "$2" | tr -d '\r')" = "trusted comment: qsh $4 SHA256SUMS" ] ||
        die "SHA256SUMS is signed for another version than $4; not installing"
}

# sha256 FILE: print the hex digest
sha256() {
    if has sha256sum; then
        sha256sum "$1" | cut -d ' ' -f 1
    elif has shasum; then
        shasum -a 256 "$1" | cut -d ' ' -f 1
    elif has openssl; then
        openssl dgst -sha256 "$1" | sed 's/^.*= *//'
    else
        die "no sha256sum, shasum or openssl to verify the download"
    fi
}

detect_target() {
    os=$(uname -s)
    arch=$(uname -m)

    case "$os" in
        Linux)
            case "$arch" in
                x86_64 | amd64) arch=x86_64 ;;
                aarch64 | arm64) arch=aarch64 ;;
                armv7* | armv8l) arch=armv7 ;;
                riscv64) arch=riscv64gc ;;
                *) die "no qsh build for Linux on $arch (supported: x86_64, aarch64, armv7, riscv64); build from source: cargo install qsh-cli" ;;
            esac
            # A 64-bit kernel can run a 32-bit userland (Raspberry Pi OS): match the userland.
            if [ "$arch" = aarch64 ] && [ "$(getconf LONG_BIT 2>/dev/null || echo 64)" = 32 ]; then
                arch=armv7
            fi
            if [ "$arch" = armv7 ]; then
                target=armv7-unknown-linux-musleabihf
            else
                target="$arch-unknown-linux-musl"
            fi
            ;;
        Darwin)
            case "$arch" in
                x86_64)
                    # A shell under Rosetta reports x86_64 on Apple silicon: install the native build.
                    if [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then
                        arch=aarch64
                    fi
                    ;;
                arm64 | aarch64) arch=aarch64 ;;
                *) die "no qsh build for macOS on $arch" ;;
            esac
            target="$arch-apple-darwin"
            ;;
        *)
            die "no qsh build for $os (supported: Linux, macOS); build from source: cargo install qsh-cli"
            ;;
    esac
}

on_path() {
    case ":${PATH:-}:" in
        *":$1:"*) return 0 ;;
        *) return 1 ;;
    esac
}

# install_file SRC DEST MODE: replace DEST atomically (a running qsh-server keeps its old inode)
install_file() {
    dest_dir=$(dirname "$2")
    mkdir -p "$dest_dir" || die "cannot create $dest_dir (try --prefix, or run as root)"
    tmp_dest="$dest_dir/.$(basename "$2").qsh-install.$$"
    cp "$1" "$tmp_dest" || die "cannot write to $dest_dir (try --prefix, or run as root)"
    chmod "$3" "$tmp_dest"
    mv -f "$tmp_dest" "$2" || {
        rm -f "$tmp_dest"
        die "cannot replace $2"
    }
}

main() {
    version="${QSH_VERSION:-latest}"
    prefix="${QSH_PREFIX:-}"
    server_only="${QSH_SERVER_ONLY:-0}"
    require_signature="${QSH_REQUIRE_SIGNATURE:-0}"
    base_url="${QSH_DOWNLOAD_URL:-$QSH_REPO_URL}"

    while [ $# -gt 0 ]; do
        case "$1" in
            --version)
                [ $# -ge 2 ] || die "--version needs a value"
                version="$2"
                shift 2
                ;;
            --version=*)
                version="${1#--version=}"
                shift
                ;;
            --prefix)
                [ $# -ge 2 ] || die "--prefix needs a value"
                prefix="$2"
                shift 2
                ;;
            --prefix=*)
                prefix="${1#--prefix=}"
                shift
                ;;
            --server-only)
                server_only=1
                shift
                ;;
            --require-signature)
                require_signature=1
                shift
                ;;
            -h | --help)
                usage
                exit 0
                ;;
            *)
                die "unknown option: $1 (see --help)"
                ;;
        esac
    done

    if [ -z "$prefix" ]; then
        if [ "$(id -u)" = 0 ]; then
            prefix=/usr/local
        else
            [ -n "${HOME:-}" ] || die "HOME is not set; use --prefix"
            prefix="$HOME/.local"
        fi
    fi
    bindir="$prefix/bin"

    detect_target

    case "$version" in
        latest) release_url="$base_url/latest/download" ;;
        v*) release_url="$base_url/download/$version" ;;
        *) release_url="$base_url/download/v$version" ;;
    esac

    has tar || die "tar is not installed"
    has gzip || die "gzip is not installed"

    tmp=$(mktemp -d 2>/dev/null || mktemp -d -t qsh-install) || die "cannot create a temporary directory"
    # shellcheck disable=SC2064 # expand $tmp now: it is set once and never changes
    trap "rm -rf '$tmp'" EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    # The checksum list names every asset, so it also tells which version "latest" is.
    download "$release_url/SHA256SUMS" "$tmp/SHA256SUMS" ||
        die "cannot download $release_url/SHA256SUMS (is version '$version' released?)"
    line=$(grep -E "[ *]qsh-[^ ]+-$target\.tar\.gz\$" "$tmp/SHA256SUMS" | head -n 1) || true
    [ -n "$line" ] || die "release '$version' has no build for $target"
    expected=$(printf '%s\n' "$line" | cut -d ' ' -f 1)
    asset=$(printf '%s\n' "$line" | sed 's/^[0-9a-fA-F]* [ *]//')
    asset_version=${asset#qsh-}
    asset_version=${asset_version%"-$target.tar.gz"}

    if download "$release_url/SHA256SUMS.minisig" "$tmp/SHA256SUMS.minisig"; then
        if verify_signature "$tmp/SHA256SUMS" "$tmp/SHA256SUMS.minisig" "$tmp" "$asset_version"; then
            say "SHA256SUMS: signature OK (qsh release key)"
        elif [ "$require_signature" = 1 ]; then
            die "cannot check the release signature here (install minisign or OpenSSL 3); not installing"
        else
            say "warning: cannot check the release signature here (install minisign or OpenSSL 3); relying on https"
        fi
    else
        die "cannot download $release_url/SHA256SUMS.minisig: the release is not signed; not installing"
    fi

    say "downloading qsh $asset_version for $target"
    download "$release_url/$asset" "$tmp/$asset" || die "cannot download $release_url/$asset"

    actual=$(sha256 "$tmp/$asset")
    [ "$actual" = "$expected" ] || die "checksum mismatch for $asset (expected $expected, got $actual); not installing"

    mkdir "$tmp/x"
    (cd "$tmp/x" && gzip -dc "../$asset" | tar -xf -) || die "cannot unpack $asset"
    src="$tmp/x/qsh-$asset_version-$target"
    [ -d "$src" ] || die "unexpected archive layout in $asset"

    if [ "$server_only" = 1 ]; then
        programs="qsh-server"
    else
        programs="qsh qsh-server"
    fi
    for p in $programs; do
        [ -f "$src/$p" ] || die "$asset does not contain $p"
        install_file "$src/$p" "$bindir/$p" 755
    done

    if [ "$server_only" != 1 ]; then
        # Man pages and completions are optional parts of the archive.
        for page in "$src"/man/*.[1-8]; do
            [ -f "$page" ] || continue
            section=${page##*.}
            install_file "$page" "$prefix/share/man/man$section/$(basename "$page")" 644
        done
        for f in "$src"/completions/*; do
            [ -f "$f" ] || continue
            name=$(basename "$f")
            case "$name" in
                *.bash) install_file "$f" "$prefix/share/bash-completion/completions/${name%.bash}" 644 ;;
                _*) install_file "$f" "$prefix/share/zsh/site-functions/$name" 644 ;;
                *.fish) install_file "$f" "$prefix/share/fish/vendor_completions.d/$name" 644 ;;
            esac
        done
    fi

    for p in $programs; do
        say "installed $bindir/$p"
    done
    if ! on_path "$bindir"; then
        say "warning: $bindir is not in PATH; add it in your shell profile:"
        say "    export PATH=\"$bindir:\$PATH\""
    fi
    if [ "$server_only" != 1 ]; then
        say "done: try 'qsh HOST'; HOST needs qsh-server too: run this script there with --server-only"
    fi
}

main "$@"
