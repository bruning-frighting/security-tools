Deliberately empty: no /etc/passwd, so users and their home directories cannot
be enumerated. Proves the check returns INSUFFICIENT_DATA instead of claiming
that no authorized_keys entries exist.
