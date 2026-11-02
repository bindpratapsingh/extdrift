"""Derive docker/seccomp-browser.json from Docker's default seccomp profile.

    curl -fsSL https://raw.githubusercontent.com/moby/moby/v28.3.0/profiles/seccomp/default.json \
        -o /tmp/moby-default.json
    python docker/build_seccomp.py /tmp/moby-default.json docker/seccomp-browser.json

The default profile hides the namespace syscalls behind CAP_SYS_ADMIN. The browser container
runs with no capabilities at all, and the browsers' own process sandboxes need unprivileged user
namespaces, so these syscalls are allowed unconditionally. Everything else stays denied, and
ptrace-family calls are removed because nothing in the sandbox has a reason to inspect another
process.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ALLOW_FOR_BROWSER_SANDBOX = ["chroot", "clone", "setns", "unshare"]
REMOVE = {"ptrace", "process_vm_readv", "process_vm_writev", "kcmp", "pidfd_getfd"}


def build(source: dict) -> dict:
    syscalls = []
    for rule in source["syscalls"]:
        names = [name for name in rule["names"] if name not in REMOVE]
        if names:
            syscalls.append({**rule, "names": names})
    syscalls.append({"names": ALLOW_FOR_BROWSER_SANDBOX, "action": "SCMP_ACT_ALLOW"})
    return {**source, "syscalls": syscalls}


if __name__ == "__main__":
    profile = build(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")))
    Path(sys.argv[2]).write_text(json.dumps(profile, indent=1) + "\n", encoding="utf-8")
