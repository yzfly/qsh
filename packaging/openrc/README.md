# qsh-server and OpenRC

qsh-server needs no init system: `qsh host` runs `qsh-server bootstrap` over ssh, which starts the
user's daemon on demand when it is not already running. That is the default and the recommended way
on OpenRC systems too.

`qsh-server` in this directory is for hosts that want a user's daemon supervised by the init
system: started at boot, restarted when it exits, logging to syslog. The daemon belongs to one
user, so the script is multiplexed by its name, one instance per user:

```sh
install -Dm755 packaging/openrc/qsh-server /etc/init.d/qsh-server
ln -s qsh-server /etc/init.d/qsh-server.alice
rc-update add qsh-server.alice default
rc-service qsh-server.alice start
```

Output goes to syslog through `logger` (tag `qsh-server.alice`). Extra daemon arguments go in
`/etc/conf.d/qsh-server.alice` as `QSH_SERVER_OPTS="..."`.

OpenRC 0.60 and later can also run user services (`rc-service --user`); once that is common in
distributions, a user-level script will replace the per-user root-managed instances.
