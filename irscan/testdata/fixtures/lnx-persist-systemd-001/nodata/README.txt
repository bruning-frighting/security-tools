Deliberately empty: this host has no systemd unit directory at all.
Proves the check returns INSUFFICIENT_DATA rather than NOT_DETECTED.
Reporting NOT_DETECTED here would tell an analyst that a host which does not
even use systemd is free of systemd persistence, which is meaningless.
