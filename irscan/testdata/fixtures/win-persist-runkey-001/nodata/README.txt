Deliberately empty: no Startup folder, and the check's Cases() supplies an
UnavailableRegistry. Proves that with no registry to read the check returns
INSUFFICIENT_DATA rather than asserting the host is free of Run-key
persistence on the basis of never having looked.
