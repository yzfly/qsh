#!/bin/bash
# Build, lint, install and smoke-test the Arch Linux package in an archlinux container, as root
# (makepkg runs as an unprivileged user):
#
#   docker run --rm -v "$PWD:/src" -w /src archlinux:latest \
#     packaging/ci/arch.sh dist/qsh-VERSION.tar.gz out
#
# The tarball takes the place of the download in the PKGBUILD's source=, and its checksum is
# regenerated (updpkgsums); the PKGBUILD is otherwise used as it is in the AUR.
set -euxo pipefail

src=$(realpath "$1")
out=$(realpath -m "$2")
here=$(dirname "$(realpath "$0")")
version=$(basename "$src" .tar.gz)
version=${version#qsh-}

# The container image keeps man pages and docs out of installed packages; the smoke test needs them.
sed -i '/^NoExtract/d' /etc/pacman.conf
pacman -Syu --noconfirm --needed base-devel namcap pacman-contrib rust man-db
mkdir -p "$out"

useradd --create-home builder
dir=/home/builder/qsh
mkdir -p "$dir"
sed "s/^pkgver=.*/pkgver=$version/" "$here/../arch/PKGBUILD" > "$dir/PKGBUILD"
cp "$src" "$dir/qsh-$version.tar.gz"
chown -R builder: "$dir"

cd "$dir"
su builder -c 'updpkgsums && makepkg --noconfirm --cleanbuild && makepkg --printsrcinfo > .SRCINFO'

# namcap: everything is reported; errors (" E: ") fail the job. Not on the -debug package, whose
# build-id links point into the main package.
namcap PKGBUILD "qsh-$version-"*"-$(uname -m).pkg.tar.zst" 2>&1 | tee "$out/namcap.txt"
if grep -q ' E: ' "$out/namcap.txt"; then
	echo "namcap found errors" >&2
	exit 1
fi

cp ./*.pkg.tar.zst PKGBUILD .SRCINFO "$out/"
ls -l "$out"

pacman -U --noconfirm "./qsh-$version-"*"-$(uname -m).pkg.tar.zst"
pacman -Ql qsh | tee "$out/files.txt"
for f in /usr/bin/qsh /usr/bin/qsh-server /usr/lib/systemd/user/qsh-server.service \
	/usr/share/man/man1/qsh.1.gz /usr/share/man/man1/qsh-server.1.gz \
	/usr/share/man/man5/qsh_config.5.gz \
	/usr/share/bash-completion/completions/qsh /usr/share/bash-completion/completions/qsh-server \
	/usr/share/zsh/site-functions/_qsh /usr/share/zsh/site-functions/_qsh-server \
	/usr/share/fish/vendor_completions.d/qsh.fish /usr/share/fish/vendor_completions.d/qsh-server.fish \
	/usr/share/licenses/qsh/LICENSE-MIT /usr/share/doc/qsh/README.md; do
	test -e "$f" || { echo "missing: $f" >&2; exit 1; }
done
su builder -c "sh '$here/smoke.sh' '$version'"
