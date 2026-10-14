Deliberately empty and unreachable (the no_data case additionally denies '/'
in persist checks that need it). Proves INSUFFICIENT_DATA rather than
NOT_DETECTED when no staging directory can be examined.
