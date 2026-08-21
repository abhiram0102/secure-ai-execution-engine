"""
sandbox_engine.py
Builds the bwrap launch command from a policy dict + job dict.

Security flags applied:
  --unshare-net          always — sandbox has no host network (only loopback)
  --cap-drop ALL         always — all Linux capabilities dropped permanently
  --unshare-user/pid/ipc/uts — full namespace isolation
"""
import logging
import os
import sysconfig
from abc import ABC, abstractmethod
from typing import Any, Dict, List


def _sandbox_pythonpath() -> str:
    """PYTHONPATH for the sandbox (python3 -S disables the site module)."""
    seen:  set       = set()
    paths: List[str] = []
    for key in ("purelib", "platlib"):
        p = sysconfig.get_paths().get(key)
        if p and p not in seen:
            paths.append(p)
            seen.add(p)
    debian_shared = "/usr/lib/python3/dist-packages"
    if debian_shared not in seen:
        paths.append(debian_shared)
    return ":".join(paths)


class SandboxEngineError(Exception):
    pass


class SandboxEngine(ABC):
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def build_command(self, policy: Dict[str, Any], job: Dict[str, Any]) -> List[str]: ...

    @classmethod
    def create(cls, engine_name: str) -> "SandboxEngine":
        registry: Dict[str, type] = {
            "bwrap":      BubblewrapEngine,
        }
        if engine_name not in registry:
            raise SandboxEngineError(f"Unknown engine: {engine_name!r}")
        return registry[engine_name]()


# System paths always mounted read-only so Python interpreter can load.
_SYSTEM_RO_BINDS = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc/alternatives"]


def _ro_bind_if_exists(path: str) -> List[str]:
    return ["--ro-bind", path, path] if os.path.exists(path) else []


class BubblewrapEngine(SandboxEngine):

    def name(self) -> str:
        return "bwrap"

    def build_command(self, policy: Dict[str, Any], job: Dict[str, Any]) -> List[str]:
        argv: List[str] = [
            "bwrap",
            "--new-session",
            "--unshare-user",   # uid 0 inside → host uid outside
            "--unshare-pid",    # isolated process tree
            "--unshare-uts",    # isolated hostname
            "--unshare-ipc",    # no shared memory with host
            "--unshare-net",    # NO host network — only loopback inside sandbox
            "--cap-drop", "ALL",# all capabilities dropped
            "--die-with-parent",# SIGKILL sandbox if supervisor dies
            "--clearenv",       # wipe all env vars; re-add below selectively
        ]

        # System library mounts (read-only — Python interpreter needs them)
        for path in _SYSTEM_RO_BINDS:
            argv.extend(_ro_bind_if_exists(path))

        argv += [
            "--tmpfs", "/tmp",  # isolated scratch space — NOT host /tmp
                                # size capped by RLIMIT_FSIZE (10MB) set in preexec
            "--proc", "/proc",
            "--dev",  "/dev",
        ]

        # Policy filesystem mounts
        for entry in policy.get("filesystem", {}).get("allowed", []):
            host_path    = os.path.abspath(entry["host_path"])
            sandbox_path = entry["sandbox_path"]
            writable     = "write_file" in entry.get("access", [])

            if not os.path.exists(host_path):
                logging.warning("[sandbox_engine] '%s' does not exist, skipping", host_path)
                continue

            argv += ["--bind" if writable else "--ro-bind", host_path, sandbox_path]

        # /opt: dispatcher.py lives here (COPY'd in image)
        argv += ["--ro-bind", "/opt", "/opt"]

        # Live-reload: if dispatcher.py is volume-mounted, bind it directly so
        # bwrap sees the live file (Docker volume mounts don't propagate into
        # bwrap's namespace via the /opt bind-mount above).
        live = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "advanced-sandbox", "dispatcher.py",
        )
        if os.path.isfile(live):
            argv += ["--ro-bind", live, "/opt/dispatcher.py"]

        # Egress proxy Unix socket dir (bind-mounted so bridge thread can reach it)
        egress_sock_dir = job.get("egress_sock_dir", "")
        if egress_sock_dir and os.path.isdir(egress_sock_dir):
            argv += ["--ro-bind", egress_sock_dir, egress_sock_dir]

        # AI code + request injected directly via pipe FDs — no temp dir on disk
        argv += [
            "--dir", "/sandbox",
            "--file",          str(job["code_fd"]), "/sandbox/ai_code_sandbox.py",
            "--ro-bind-data",  str(job["req_fd"]),  "/sandbox/request.json",
        ]

        # Seccomp BPF filter — applied by bwrap before any code runs
        seccomp_fd = job.get("seccomp_fd", -1)
        if seccomp_fd >= 0:
            argv += ["--seccomp", str(seccomp_fd)]


        # Environment (minimal — only what the sandbox legitimately needs)
        argv += [
            "--chdir", "/sandbox",
            "--setenv", "PATH",       "/usr/bin:/bin",
            "--setenv", "PYTHONPATH", _sandbox_pythonpath(),
        ]
        for key, val in job.get("env", {}).items():
            argv += ["--setenv", key, str(val)]

        # NOTE: the final command (python3 -S /opt/dispatcher.py) is appended
        # by the supervisor AFTER adding DB socket bind-mounts, so it is not
        # included here.
        return argv
