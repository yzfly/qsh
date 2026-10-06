#!/bin/bash
# Build, test and audit the Homebrew formula on macOS (or Linux with Homebrew) from a local
# source tarball:
#
#   packaging/ci/homebrew.sh dist/qsh-VERSION.tar.gz out
#
# Homebrew installs formulae only from taps, so this puts a copy of packaging/homebrew/qsh.rb,
# with url pointing at the tarball (file://) and its sha256, into a local tap yzfly/local, then
# builds a bottle from source, runs `brew test` and the smoke test, and `brew audit --strict`
# (reported, not fatal: some checks only make sense for a published release).
set -euxo pipefail

src=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
mkdir -p "$2"
out=$(cd "$2" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
version=$(basename "$src" .tar.gz)
version=${version#qsh-}
sha=$(shasum -a 256 "$src" | cut -d ' ' -f 1)

export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_CLEANUP=1 HOMEBREW_NO_ENV_HINTS=1
brew tap-new --no-git yzfly/local
tap=$(brew --repository yzfly/local)
sed -e "s|^  url \".*\"|  url \"file://$src\"|" -e "s|^  sha256 \".*\"|  sha256 \"$sha\"|" \
	"$here/../homebrew/qsh.rb" > "$tap/Formula/qsh.rb"
grep -E '^  (url|sha256) ' "$tap/Formula/qsh.rb"

brew install --build-bottle --verbose yzfly/local/qsh
brew test --verbose yzfly/local/qsh
(cd "$out" && brew bottle --skip-relocation --no-rebuild --root-url=https://example.invalid yzfly/local/qsh) ||
	echo "::warning title=Homebrew::brew bottle failed"
cp "$tap/Formula/qsh.rb" "$out/qsh.rb"

brew audit --strict --formula yzfly/local/qsh 2>&1 | tee "$out/audit.txt" ||
	echo "::warning title=Homebrew::brew audit --strict reported problems (see audit.txt)"

brew list --verbose qsh | tee "$out/files.txt"
prefix=$(brew --prefix)
for f in bin/qsh bin/qsh-server share/man/man1/qsh.1 share/man/man1/qsh-server.1 \
	share/man/man5/qsh_config.5 etc/bash_completion.d/qsh share/zsh/site-functions/_qsh \
	share/fish/vendor_completions.d/qsh.fish; do
	test -e "$prefix/$f" || { echo "missing: $prefix/$f" >&2; exit 1; }
done
sh "$here/smoke.sh" "$version"
