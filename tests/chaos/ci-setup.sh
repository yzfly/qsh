#!/bin/sh
# Prepare a disposable Ubuntu machine (a GitHub Actions runner) for the chaos tests: the tools of
# the topology, sshd, and the kernel modules for netem and NAT. Needs root. `--mosh` also
# installs mosh, for the benchmark.
set -eu
packages="iproute2 nftables ethtool openssh-server openssh-client conntrack"
[ "${1:-}" = --mosh ] && packages="$packages mosh"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
# shellcheck disable=SC2086
apt-get install -y -qq --no-install-recommends $packages >/dev/null
# netem is in linux-modules-extra on some cloud kernels
if ! modprobe sch_netem 2>/dev/null; then
    apt-get install -y -qq "linux-modules-extra-$(uname -r)" >/dev/null
    modprobe sch_netem
fi
for module in nf_conntrack nft_masq nf_nat; do modprobe "$module" 2>/dev/null || true; done
# The C.UTF-8 locale for mosh and the shells
locale -a | grep -qi '^c\.utf-\?8$' || echo "ci-setup: no C.UTF-8 locale" >&2
echo "ci-setup: kernel $(uname -r), $(tc -V 2>&1 | head -1), $(nft --version), $(ssh -V 2>&1)"
