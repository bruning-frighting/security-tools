Deliberately empty: no /etc/passwd, so no accounts or home directories can be
enumerated. Proves the check returns INSUFFICIENT_DATA rather than asserting no
credentials exist anywhere on the host.
