#!/bin/sh
# Image setup for the end-to-end tests, run as root by the Dockerfile: install sshd with the
# distribution's package manager and create the user `test`. Nothing qsh-specific is installed:
# the point is that qsh-server, a static binary in ~/.local/bin, needs nothing from the host.
set -eu

if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q
    apt-get install -y -q --no-install-recommends openssh-server
    rm -rf /var/lib/apt/lists/*
elif command -v dnf >/dev/null 2>&1; then
    dnf -y -q install openssh-server shadow-utils
    dnf clean all
elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache openssh-server
elif command -v pacman >/dev/null 2>&1; then
    pacman -Syu --noconfirm --needed openssh
    pacman -Scc --noconfirm
elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install --no-recommends openssh-server shadow
    zypper clean --all
else
    echo "setup.sh: no supported package manager (apt-get, dnf, apk, pacman, zypper)" >&2
    exit 1
fi

if command -v useradd >/dev/null 2>&1; then
    useradd --create-home --shell /bin/sh test
else
    adduser -D -s /bin/sh test # busybox (Alpine)
fi
# useradd/adduser lock the password ("!" or "!!"); sshd then refuses even key logins without
# PAM. "*" means: no password, not locked.
sed -i 's/^test:[^:]*:/test:*:/' /etc/shadow

ssh-keygen -A
mkdir -p /run/sshd /var/empty
chmod 0755 /run/sshd

# pam_loginuid fails in unprivileged containers and, when required, aborts the session.
for f in /etc/pam.d/sshd /usr/lib/pam.d/sshd; do
    if [ -f "$f" ]; then
        sed -i 's/^\(session[[:space:]]\{1,\}\)required\([[:space:]]\{1,\}pam_loginuid\.so\)/\1optional\2/' "$f"
    fi
done
