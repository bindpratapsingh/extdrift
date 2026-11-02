"""Prove the isolation from inside the container, on every run.

The hardening flags say what was requested; this module checks what was received. A run whose
preflight fails is never scored, so a misconfigured host produces an explicit failure rather than a
report that wrongly claims isolation. Standard library only.

The egress probes are TCP connects to public resolvers, the host and the cloud metadata address,
sending no data. They must fail. The reachable-gateway probe must succeed, because if it did not,
the "no egress" results could simply mean that networking as a whole was broken.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import time
from pathlib import Path

GATEWAY_WAIT_SECONDS = 45.0

#: Destinations that must be unreachable. Includes Docker Desktop's names for the host.
EGRESS_TARGETS = (
    ("1.1.1.1", 443), ("8.8.8.8", 53), ("169.254.169.254", 80),
    ("host.docker.internal", 22), ("gateway.docker.internal", 22),
    ("kubernetes.docker.internal", 6443),
)
ALLOWED_ENV_PREFIXES = ("EXTDRIFT_", "PLAYWRIGHT_", "PYTHON", "PIP_", "PATH", "HOME", "HOSTNAME",
                        "LANG", "GPG_KEY", "SETUPTOOLS_", "TMPDIR", "MOZ_", "SE_", "PWD", "OLDPWD",
                        "SHLVL", "_")
#: Environment names that would show host credentials had leaked in.
SENSITIVE_ENV_WORDS = ("TOKEN", "SECRET", "PASSWORD", "AWS_", "GITHUB", "SSH_", "API_KEY", "CREDENTIAL")
HOST_PATH_HINTS = ("/host_mnt", "/Users/", "/run/host", "/mnt/host", "/var/run/docker.sock")


def _status_field(name: str) -> str | None:
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith(name + ":"):
            return line.split(":", 1)[1].strip()
    return None


def _unwritable(path: str) -> bool:
    probe = Path(path) / ".extdrift-write-probe"
    try:
        probe.write_text("x")
    except OSError:
        return True
    probe.unlink(missing_ok=True)
    return False


def _connects(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _cgroup_limit(name: str) -> str | None:
    try:
        return Path("/sys/fs/cgroup", name).read_text().strip()
    except OSError:
        return None


def run_checks(role: str, gateway: str | None = None, *, control_token: str | None = None) -> dict:
    """Return {passed, checks: [{name, passed, detail}]} for this container."""
    checks: list[dict] = []

    def check(name: str, passed: bool, detail: object = "") -> None:
        checks.append({"name": name, "passed": bool(passed), "detail": str(detail)[:300]})

    uid = os.getuid()
    check("runs_as_non_root", uid != 0, f"uid={uid}")
    cap_eff = _status_field("CapEff") or ""
    check("no_effective_capabilities", int(cap_eff or "1", 16) == 0, f"CapEff={cap_eff}")
    check("no_new_privileges", _status_field("NoNewPrivs") == "1", _status_field("NoNewPrivs"))
    check("seccomp_filter_active", _status_field("Seccomp") == "2", _status_field("Seccomp"))
    check("root_filesystem_read_only", _unwritable("/") and _unwritable("/opt"), "")
    check("docker_socket_absent", not Path("/var/run/docker.sock").exists()
          and not Path("/run/docker.sock").exists(), "")

    mounts = Path("/proc/self/mountinfo").read_text()
    leaked = [hint for hint in HOST_PATH_HINTS if hint in mounts]
    check("no_host_directories_mounted", not leaked, leaked)

    sensitive = [name for name in os.environ
                 if any(word in name.upper() for word in SENSITIVE_ENV_WORDS)
                 and name not in ("EXTDRIFT_CONTROL_TOKEN", "GPG_KEY")]
    unexpected = [name for name in os.environ if not name.startswith(ALLOWED_ENV_PREFIXES)]
    check("no_host_credentials_in_environment", not sensitive, sensitive)
    check("environment_is_allow_listed", not unexpected, unexpected)

    memory = _cgroup_limit("memory.max")
    pids = _cgroup_limit("pids.max")
    check("memory_limit_applied", memory not in (None, "max"), memory)
    check("pid_limit_applied", pids not in (None, "max"), pids)

    reachable = [f"{host}:{port}" for host, port in EGRESS_TARGETS if _connects(host, port)]
    check("egress_blocked", not reachable, reachable or "all probes failed to connect")
    try:
        resolved = socket.gethostbyname("example.com")
    except OSError:
        resolved = None
    check("external_dns_blocked", resolved is None, resolved or "resolution failed")

    if role == "browser" and gateway:
        host, _, port = gateway.partition(":")
        # The gateway runs its own preflight before it starts listening, so allow it time.
        end = time.monotonic() + GATEWAY_WAIT_SECONDS
        while not (reached := _connects(host, int(port or 8080))) and time.monotonic() < end:
            time.sleep(0.5)
        check("gateway_reachable", reached, gateway)
        check("input_read_only", _unwritable("/input"), "")

    return {"role": role, "passed": all(c["passed"] for c in checks), "checks": checks}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", required=True, choices=("browser", "gateway"))
    parser.add_argument("--gateway")
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    result = run_checks(args.role, args.gateway)
    Path(args.out).write_text(json.dumps(result, indent=2), encoding="utf-8")
    # A failed preflight must stop the gateway too; the host then reports why from the evidence.
    return 0 if result["passed"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
