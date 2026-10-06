#!/bin/sh
# Container entry point: put the test key and qsh-server in place for the user `test`, then run
# sshd in the foreground on port 2222, logging to the container's stderr (`docker logs`).
set -eu

home=/home/test
group=$(id -gn test)

mkdir -p "$home/.ssh" "$home/.local/bin"
cp /qsh-in/authorized_keys "$home/.ssh/authorized_keys"
cp /qsh-in/qsh-server "$home/.local/bin/qsh-server"
chmod 0700 "$home/.ssh"
chmod 0600 "$home/.ssh/authorized_keys"
chmod 0755 "$home/.local/bin/qsh-server"
chown -R "test:$group" "$home"

# Files that make sshd refuse non-root logins while "booting"
rm -f /run/nologin /var/run/nologin /etc/nologin

sshd=$(command -v sshd || echo /usr/sbin/sshd)
set -- -D -e -p 2222 -o PasswordAuthentication=no -o PermitRootLogin=no
# OpenSSH 9.8+ penalizes sources with many failed sessions; tests reconnect a lot from one address.
if "$sshd" -t -o PerSourcePenalties=no 2>/dev/null; then
    set -- "$@" -o PerSourcePenalties=no
fi
"$sshd" -t "$@"
exec "$sshd" "$@"
