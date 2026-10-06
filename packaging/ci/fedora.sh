#!/bin/bash
# Build, lint, install and smoke-test the RPMs in a Fedora container, as root (rpmbuild itself
# runs as an unprivileged user, like in mock):
#
#   docker run --rm -v "$PWD:/src" -w /src fedora:latest \
#     packaging/ci/fedora.sh dist/qsh-VERSION.tar.gz dist/qsh-VERSION-vendor.tar.xz out
#
# Builds with `--with vendor` (crates from the vendor tarball). With - for the vendor tarball it
# builds the way Fedora itself has to: crates from Fedora's rust-*-devel packages, BuildRequires
# from %generate_buildrequires; it first writes out/fedora-crates.txt, which of those Fedora has.
# Either way the packages are then linted, installed and smoke-tested.
set -euxo pipefail

src=$(realpath "$1")
vendor=$2
[ "$vendor" = - ] || vendor=$(realpath "$vendor")
out=$(realpath -m "$3")
here=$(dirname "$(realpath "$0")")
spec_in=$here/../rpm/qsh.spec
version=$(basename "$src" .tar.gz)
version=${version#qsh-}

dnf -y -q install rpm-build rpmlint 'dnf-command(builddep)' man-db
mkdir -p "$out"

useradd --create-home builder
top=/home/builder/rpmbuild
mkdir -p "$top"/{SOURCES,SPECS}
cp "$src" "$top/SOURCES/qsh-$version.tar.gz"
[ "$vendor" = - ] || cp "$vendor" "$top/SOURCES/qsh-$version-vendor.tar.xz"
sed "s/^Version:.*/Version:        $version/" "$spec_in" > "$top/SPECS/qsh.spec"
chown -R builder: "$top"

if [ "$vendor" = - ]; then
	dnf -y -q builddep "$top/SPECS/qsh.spec"
	dnf -y -q install cargo rust
	# The generated BuildRequires (crate(NAME/FEATURE) ranges), and which Fedora provides.
	# rpmbuild -br exits 11 ("Failed build dependencies") while they are not installed yet: that
	# is how it hands them over, in the buildreqs.nosrc.rpm (mock does the same loop).
	su builder -c "rpmbuild -br '$top/SPECS/qsh.spec'" || true
	rpm -qp --requires "$top"/SRPMS/qsh-*.buildreqs.nosrc.rpm | grep 'crate(' | sort -u |
		while read -r dep; do
			if [ -n "$(dnf -q repoquery --whatprovides "$dep" 2> /dev/null)" ]; then
				echo "ok       $dep"
			else
				echo "MISSING  $dep"
			fi
		done | tee "$out/fedora-crates.txt"
	echo "::notice title=Fedora crates::$(grep -c '^ok' "$out/fedora-crates.txt") of $(wc -l < "$out/fedora-crates.txt") crate BuildRequires available, see fedora-crates.txt"
	# With documentation (tsflags= overrides the image's nodocs): rust-*-devel marks a crate's
	# README.md %doc, and many crates compile it in (#![doc = include_str!("../README.md")]).
	# Koji and mock install docs; a nodocs install breaks the build ("couldn't read README.md").
	dnf -y -q --setopt=tsflags= builddep "$top"/SRPMS/qsh-*.buildreqs.nosrc.rpm
	su builder -c "rpmbuild -ba '$top/SPECS/qsh.spec'"
else
	dnf -y -q builddep --define '_with_vendor --with-vendor' "$top/SPECS/qsh.spec"
	su builder -c "rpmbuild -ba --with vendor '$top/SPECS/qsh.spec'"
fi

# Not the buildreqs.nosrc.rpm of the Fedora-crates route.
cp "$top"/RPMS/*/*.rpm "$top"/SRPMS/*.src.rpm "$out/"
cd "$out"
ls -l

# rpmlint: everything is reported; errors fail the job (exit status 64; 66 is the badness
# threshold, which Fedora does not set).
set +e
rpmlint "$top/SPECS/qsh.spec" ./*.rpm 2>&1 | tee rpmlint.txt
lint=${PIPESTATUS[0]}
set -e
[ "$lint" -eq 0 ] || [ "$lint" -eq 66 ] || { echo "rpmlint found errors" >&2; exit 1; }

arch=$(rpm --eval '%{_arch}')
# The container image sets tsflags=nodocs; the smoke test needs the man pages.
dnf -y -q --setopt=tsflags= install "./qsh-$version-"*".$arch.rpm" "./qsh-server-$version-"*".$arch.rpm"
rpm -ql qsh qsh-server | tee files.txt
rpm -q --provides qsh | tee provides.txt
for f in /usr/bin/qsh /usr/bin/qsh-server /usr/lib/systemd/user/qsh-server.service \
	/usr/share/man/man1/qsh.1.gz /usr/share/man/man1/qsh-server.1.gz \
	/usr/share/man/man5/qsh_config.5.gz \
	/usr/share/bash-completion/completions/qsh /usr/share/bash-completion/completions/qsh-server \
	/usr/share/zsh/site-functions/_qsh /usr/share/zsh/site-functions/_qsh-server \
	/usr/share/fish/vendor_completions.d/qsh.fish /usr/share/fish/vendor_completions.d/qsh-server.fish \
	/usr/share/licenses/qsh/LICENSE-MIT /usr/share/licenses/qsh-server/LICENSE-MIT; do
	test -e "$f" || { echo "missing: $f" >&2; exit 1; }
done
su builder -c "sh '$here/smoke.sh' '$version'"
