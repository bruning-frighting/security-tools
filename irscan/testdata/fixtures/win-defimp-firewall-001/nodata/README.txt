Registry-only check. The nodata case's registry contents are defined by the
FakeRegistry in internal/checks/defimp_win.go; this tree exists so the filesystem
root is valid. The nodata case supplies no registry at all, so the check
must return INSUFFICIENT_DATA.
