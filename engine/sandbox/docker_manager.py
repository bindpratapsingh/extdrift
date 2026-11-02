"""Host-side lifecycle of one sandboxed run: network, volumes, containers, cleanup.

The host talks to Docker only through the CLI, so no Docker SDK dependency is added and nothing
inside a container ever holds the Docker socket.

Isolation layout for one run::

    <run>-net   --internal Docker network: no gateway, no NAT, no route to the host or internet
      <run>-gateway   mitmproxy, writes evidence to <run>-evidence
      <run>-browser   the extension, reads <run>-input, writes its own view to <run>-output

No host path is ever mounted. Data goes in and out as tar streams through short-lived helper
containers with networking disabled. Files read back are size-limited and treated as hostile.
"""

from __future__ import annotations

import io
import json
import logging
import secrets
import subprocess
import tarfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from engine.pipeline.config import REPO_ROOT

log = logging.getLogger("extdrift.sandbox")

LABEL = "extdrift.sandbox=1"
GATEWAY_PORT = 8080
SANDBOX_USER = "1000:1000"


class DockerError(RuntimeError):
    """Docker is unavailable, or a Docker operation failed."""


class SandboxTimeout(DockerError):
    """The browser container exceeded its wall-clock limit and was killed."""


def _docker(*args: str, input_bytes: bytes | None = None, timeout: float = 120,
            check: bool = True) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(["docker", *args], input=input_bytes, capture_output=True,
                                timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise DockerError("Docker is not installed, or the docker command is not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise DockerError(f"docker {args[0]} timed out after {timeout}s") from exc
    if check and result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()[:800]
        raise DockerError(f"docker {' '.join(args[:2])} failed: {detail}")
    return result


def check_daemon() -> dict:
    """Return basic daemon facts, or raise DockerError with an actionable message."""
    result = _docker("version", "--format", "{{json .Server}}", check=False, timeout=20)
    if result.returncode != 0:
        raise DockerError("cannot reach the Docker daemon. Start Docker and try again. Detail: "
                          + result.stderr.decode("utf-8", "replace").strip()[:300])
    return json.loads(result.stdout)


def image_id(image: str) -> str:
    result = _docker("image", "inspect", image, "--format", "{{.Id}}", check=False, timeout=30)
    if result.returncode != 0:
        raise DockerError(f"image {image} is missing. Build it with: "
                          "python -m engine.cli sandbox-build")
    return result.stdout.decode().strip()


def build_images(config: dict, *, no_cache: bool = False) -> None:
    for name, dockerfile in (("sandbox", "docker/sandbox.Dockerfile"),
                             ("gateway", "docker/gateway.Dockerfile")):
        command = ["docker", "build", "-f", dockerfile, "-t", config["images"][name], "."]
        if no_cache:
            command.insert(2, "--no-cache")
        subprocess.run(command, cwd=REPO_ROOT, check=True)


def common_hardening() -> list[str]:
    """Flags every analysis container receives. Tested so that none can be dropped by accident."""
    return [
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--user", SANDBOX_USER,
        "--ipc", "private",
        "--cgroupns", "private",
        "--hostname", "sandbox",
        "--log-driver", "json-file", "--log-opt", "max-size=5m",
        "--label", LABEL,
    ]


def browser_arguments(config: dict) -> list[str]:
    limits = config["limits"]
    seccomp = (REPO_ROOT / config["security"]["seccomp_profile"]).resolve()
    if not seccomp.exists():
        raise DockerError(f"seccomp profile not found: {seccomp}")
    return [
        *common_hardening(),
        "--memory", limits["browser_memory"],
        "--memory-swap", limits["browser_memory"],
        "--cpus", str(limits["browser_cpus"]),
        "--pids-limit", str(limits["browser_pids"]),
        "--shm-size", limits["browser_shm"],
        "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={limits['browser_tmpfs']}",
        "--security-opt", f"seccomp={seccomp}",
    ]


def gateway_arguments(config: dict) -> list[str]:
    limits = config["limits"]
    return [
        *common_hardening(),
        "--memory", limits["gateway_memory"],
        "--memory-swap", limits["gateway_memory"],
        "--cpus", str(limits["gateway_cpus"]),
        "--pids-limit", str(limits["gateway_pids"]),
        "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={limits['gateway_tmpfs']}",
    ]


def _tar_directory(source: Path, arcname: str) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        archive.add(source, arcname=arcname, filter=_normalise_tarinfo)
    return buffer.getvalue()


def _normalise_tarinfo(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
    if not (info.isfile() or info.isdir()):
        return None
    info.uid = info.gid = 1000
    info.uname = info.gname = ""
    info.mode = 0o755 if info.isdir() else 0o644
    return info


def _tar_files(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, payload in files.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.uid, info.gid = len(payload), 0o644, 1000, 1000
            archive.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def safe_extract_stream(stream, dest: Path, *, max_total: int, max_file: int) -> dict:
    """Extract an untrusted tar stream: regular files only, no traversal, bounded sizes."""
    dest = dest.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    total = 0
    truncated: list[str] = []
    with tarfile.open(fileobj=stream, mode="r|") as archive:
        for member in archive:
            if not member.isfile():
                continue
            target = (dest / member.name).resolve()
            if not target.is_relative_to(dest):
                truncated.append(f"refused path {member.name!r}")
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                continue
            allowed = min(max_file, max_total - total)
            payload = source.read(max(allowed, 0))
            total += len(payload)
            target.write_bytes(payload)
            if member.size > len(payload):
                truncated.append(member.name)
    return {"bytes": total, "truncated": truncated}


@dataclass
class RunOutcome:
    """What one sandboxed run produced. ``exit_code`` is the browser container's."""

    exit_code: int | None
    timed_out: bool
    raw_dir: Path
    collect_notes: dict = field(default_factory=dict)
    environment: dict = field(default_factory=dict)
    logs: dict = field(default_factory=dict)


class SandboxRun:
    """One disposable sandbox. Everything it creates is removed on context exit."""

    def __init__(self, name: str, config: dict, *, browser: str, job: dict,
                 extension_dir: Path, raw_dir: Path, gateway_env: dict | None = None,
                 bundle_file: Path | None = None, on_state: Callable[[str], None] | None = None):
        self.name = name
        self.config = config
        self.browser = browser
        self.job = dict(job)
        self.extension_dir = Path(extension_dir)
        self.raw_dir = Path(raw_dir)
        self.gateway_env = dict(gateway_env or {})
        self.bundle_file = bundle_file
        self.on_state = on_state or (lambda _: None)
        self.network = f"{name}-net"
        self.volumes = {role: f"{name}-{role}" for role in ("input", "output", "evidence")}
        self.containers = {role: f"{name}-{role}" for role in ("gateway", "browser")}
        self.token = secrets.token_hex(24)
        self.created_networks: list[str] = []
        self.created_volumes: list[str] = []

    # -- setup ------------------------------------------------------------------------------

    def _create_infrastructure(self) -> None:
        _docker("network", "create", "--internal", "--label", LABEL, self.network)
        self.created_networks.append(self.network)
        for volume in self.volumes.values():
            _docker("volume", "create", "--label", LABEL, volume)
            self.created_volumes.append(volume)

    def _helper(self, volume: str, mount_options: str, *command: str,
                input_bytes: bytes | None = None, timeout: float = 120,
                user: str = SANDBOX_USER) -> subprocess.CompletedProcess:
        # Mounted at /output because a fresh volume inherits the ownership of the image
        # directory it first lands on, and that directory belongs to the unprivileged user.
        return _docker(
            "run", "--rm", "-i", "--network", "none", "--cap-drop", "ALL", "--read-only",
            "--security-opt", "no-new-privileges", "--user", user, "--label", LABEL,
            "-v", f"{volume}:/output{mount_options}", "--entrypoint", command[0],
            self.config["images"]["sandbox"], *command[1:],
            input_bytes=input_bytes, timeout=timeout)

    def _load_input(self) -> None:
        job_bytes = json.dumps(self.job, indent=2).encode()
        self._helper(self.volumes["input"], "", "tar", "-xf", "-", "-C", "/output",
                     input_bytes=_tar_directory(self.extension_dir, "ext"), timeout=300)
        self._helper(self.volumes["input"], "", "tar", "-xf", "-", "-C", "/output",
                     input_bytes=_tar_files({"job.json": job_bytes}))
        if self.bundle_file:
            self._helper(self.volumes["evidence"], "", "tar", "-xf", "-", "-C", "/output",
                         input_bytes=_tar_files({"bundle-input.json": self.bundle_file.read_bytes()}))

    def _start_gateway(self) -> str:
        env = {
            "EXTDRIFT_CONTROL_TOKEN": self.token,
            "EXTDRIFT_MAX_EVIDENCE_BYTES": str(self.config["collection"]["max_evidence_bytes"]),
            **self.gateway_env,
        }
        if self.bundle_file:
            env["EXTDRIFT_BUNDLE_FILE"] = "/evidence/bundle-input.json"
        env_flags = [flag for key, value in env.items() for flag in ("--env", f"{key}={value}")]
        _docker("run", "-d", "--name", self.containers["gateway"],
                *gateway_arguments(self.config), *env_flags,
                "--network", self.network, "--network-alias", "gateway",
                "-v", f"{self.volumes['evidence']}:/evidence",
                self.config["images"]["gateway"])
        inspect = _docker("inspect", "--format",
                          "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                          self.containers["gateway"])
        return inspect.stdout.decode().strip()

    def _run_browser(self) -> tuple[int | None, bool, str]:
        """Run the browser container to completion or its time limit."""
        command = [
            "docker", "run", "--name", self.containers["browser"],
            *browser_arguments(self.config),
            "--network", self.network,
            "--env", f"EXTDRIFT_CONTROL_TOKEN={self.token}",
            "--env", "HOME=/tmp/home",
            "-v", f"{self.volumes['input']}:/input:ro",
            "-v", f"{self.volumes['output']}:/output",
            self.config["images"]["sandbox"],
        ]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        lines: list[str] = []

        def reader() -> None:
            assert process.stdout is not None
            for raw in process.stdout:
                line = raw.decode("utf-8", "replace").rstrip()
                if line.startswith("EXTDRIFT_STATE "):
                    self.on_state(line.split(" ", 1)[1].strip())
                elif len(lines) < 400:
                    lines.append(line[:400])

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        timeout = self.config["limits"]["run_timeout_seconds"]
        timed_out = False
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _docker("kill", self.containers["browser"], check=False, timeout=30)
            process.kill()
            code = None
        thread.join(timeout=5)
        return code, timed_out, "\n".join(lines)

    # -- collection -------------------------------------------------------------------------

    def _collect(self, volume: str, dest: Path) -> dict:
        limits = self.config["collection"]
        process = subprocess.Popen(
            ["docker", "run", "--rm", "-i", "--network", "none", "--cap-drop", "ALL", "--read-only",
             "--security-opt", "no-new-privileges", "--user", SANDBOX_USER, "--label", LABEL,
             "-v", f"{volume}:/output:ro", "--entrypoint", "tar",
             self.config["images"]["sandbox"], "-cf", "-", "-C", "/output", "."],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        assert process.stdout is not None
        try:
            return safe_extract_stream(process.stdout, dest,
                                       max_total=limits["max_collected_bytes"],
                                       max_file=limits["max_collected_file_bytes"])
        finally:
            process.stdout.close()
            process.wait(timeout=60)

    def execute(self) -> RunOutcome:
        """Create the sandbox, run the job, collect the evidence. Cleanup is the caller's exit."""
        environment = {
            "sandbox_image": image_id(self.config["images"]["sandbox"]),
            "gateway_image": image_id(self.config["images"]["gateway"]),
            "docker_server_version": check_daemon().get("Version"),
            # Relative paths only: reports get shared, and a home directory path identifies its owner.
            "hardening": {"browser": [arg.replace(f"{REPO_ROOT}/", "") for arg in browser_arguments(self.config)],
                          "gateway": gateway_arguments(self.config),
                          "network": "--internal"},
        }
        self._create_infrastructure()
        self.job["gateway"] = f"gateway:{GATEWAY_PORT}"
        self._load_input()
        gateway_ip = self._start_gateway()
        environment["gateway_ip"] = gateway_ip
        code, timed_out, browser_log = self._run_browser()

        logs = {"browser": browser_log}
        gateway_log = _docker("logs", "--tail", "400", self.containers["gateway"],
                              check=False, timeout=30)
        logs["gateway"] = (gateway_log.stdout + gateway_log.stderr).decode("utf-8", "replace")
        # A graceful stop runs the addon's done hook and flushes its final summary.
        _docker("stop", "-t", "10", self.containers["gateway"], check=False, timeout=60)

        self.raw_dir.mkdir(parents=True, exist_ok=True)
        notes = {
            "output": self._collect(self.volumes["output"], self.raw_dir / "browser"),
            "evidence": self._collect(self.volumes["evidence"], self.raw_dir / "gateway"),
        }
        (self.raw_dir / "browser_container.log").write_text(logs["browser"], encoding="utf-8")
        (self.raw_dir / "gateway_container.log").write_text(logs["gateway"], encoding="utf-8")
        return RunOutcome(code, timed_out, self.raw_dir, notes, environment, logs)

    # -- teardown ---------------------------------------------------------------------------

    def cleanup(self) -> list[str]:
        """Remove everything this run created, returning anything that could not be removed."""
        problems = []
        for container in self.containers.values():
            _docker("rm", "-f", "-v", container, check=False, timeout=60)
        for network in self.created_networks:
            if _docker("network", "rm", network, check=False, timeout=60).returncode != 0:
                problems.append(f"network {network}")
        for volume in self.created_volumes:
            if _docker("volume", "rm", "-f", volume, check=False, timeout=60).returncode != 0:
                problems.append(f"volume {volume}")
        return problems

    def __enter__(self) -> "SandboxRun":
        return self

    def __exit__(self, *exc) -> None:
        problems = self.cleanup()
        if problems:
            log.warning("sandbox cleanup left resources behind: %s", problems)


def leftover_resources() -> dict[str, list[str]]:
    """Everything still labelled as belonging to the sandbox."""
    def names(*args: str) -> list[str]:
        out = _docker(*args, check=False, timeout=60).stdout.decode().split()
        return out
    return {
        "containers": names("ps", "-a", "--filter", f"label={LABEL}", "--format", "{{.Names}}"),
        "networks": names("network", "ls", "--filter", f"label={LABEL}", "--format", "{{.Name}}"),
        "volumes": names("volume", "ls", "--filter", f"label={LABEL}", "--format", "{{.Name}}"),
    }


def clean_all() -> dict[str, list[str]]:
    """Remove every sandbox resource, for recovery after a crashed host process."""
    found = leftover_resources()
    for name in found["containers"]:
        _docker("rm", "-f", "-v", name, check=False, timeout=60)
    for name in found["networks"]:
        _docker("network", "rm", name, check=False, timeout=60)
    for name in found["volumes"]:
        _docker("volume", "rm", "-f", name, check=False, timeout=60)
    return found


def wait_until_removed(deadline_s: float = 10.0) -> dict[str, list[str]]:
    end = time.monotonic() + deadline_s
    found = leftover_resources()
    while any(found.values()) and time.monotonic() < end:
        time.sleep(0.5)
        found = leftover_resources()
    return found
