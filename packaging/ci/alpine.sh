#!/bin/sh
# Build, lint, install and smoke-test the Alpine packages in an Alpine container, as root
# (abuild runs as an unprivileged member of the abuild group with its own signing key):
#
#   docker run --rm -v "$PWD:/src" -w /src alpine:latest \
#     packaging/ci/alpine.sh dist/qsh-VERSION.tar.gz out
#
# The tarball takes the place of the download in the APKBUILD's source=, and its checksum is
# regenerated; the APKBUILD is otherwise used as it is in aports.
set -eux

src=$(realpath "$1")
out=$2
here=$(dirname "$(realpath "$0")")
version=$(basename "$src" .tar.gz)
version=${version#qsh-}

apk update
apk add alpine-sdk atools mandoc
mkdir -p "$out"
out=$(realpath "$out")

adduser -D builder
addgroup builder abuild
su builder -c 'abuild-keygen -a -n'
cp /home/builder/.abuild/*.rsa.pub /etc/apk/keys/

dir=/home/builder/aports/testing/qsh
mkdir -p "$dir"
sed "s/^pkgver=.*/pkgver=$version/" "$here/../alpine/APKBUILD" > "$dir/APKBUILD"
cp "$src" "$dir/qsh-$version.tar.gz"
chown -R builder: /home/builder/aports

cd "$dir"
# apkbuild-lint (atools): reported, not fatal.
su builder -c 'apkbuild-lint APKBUILD' 2>&1 | tee "$out/apkbuild-lint.txt" || true
su builder -c 'export SRCDEST=$PWD; abuild checksum && abuild -r'

repo=/home/builder/packages/testing/$(apk --print-arch)
cp "$repo"/*.apk "$out/"
cp APKBUILD "$out/APKBUILD"
ls -l "$out"

apk add --repository /home/builder/packages/testing qsh qsh-server qsh-server-openrc qsh-doc qsh-bash-completion
apk info -L qsh qsh-server qsh-server-openrc qsh-doc qsh-bash-completion | tee "$out/files.txt"
for f in /usr/bin/qsh /usr/bin/qsh-server /etc/init.d/qsh-server \
	/usr/share/man/man1/qsh.1.gz /usr/share/man/man1/qsh-server.1.gz \
	/usr/share/man/man5/qsh_config.5.gz \
	/usr/share/bash-completion/completions/qsh /usr/share/bash-completion/completions/qsh-server \
	/usr/share/licenses/qsh/LICENSE-MIT; do
	test -e "$f" || { echo "missing: $f" >&2; exit 1; }
done
su builder -c "sh '$here/smoke.sh' '$version'"
