Deliberately empty: a pure-systemd host with no rc.local and no /etc/init.d.
Proves the check returns INSUFFICIENT_DATA. This is a common real case, and the
systemd check carries the persistence coverage on such a host.
