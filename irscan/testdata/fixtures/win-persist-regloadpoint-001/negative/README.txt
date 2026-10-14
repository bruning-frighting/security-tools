Registry-only check. The negative case's registry contents are defined by the
FakeRegistry in internal/checks/persist_win3.go; this tree exists so the filesystem
root is valid. The nodata case supplies no registry at all, so the check
must return INSUFFICIENT_DATA.
