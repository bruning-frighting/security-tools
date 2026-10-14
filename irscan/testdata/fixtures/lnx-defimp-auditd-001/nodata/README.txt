Deliberately empty: the Linux audit subsystem is not installed at all, which is
the common real-world case (and is exactly what WSL2 Kali looks like).
This is THE critical path for this check: it must return INSUFFICIENT_DATA.
Returning NOT_DETECTED would tell an analyst that a host with no audit
subsystem shows no evidence of audit tampering -- technically true and
completely misleading.
