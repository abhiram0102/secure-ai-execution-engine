#!/usr/bin/env python3
"""
supervisor.py
Orchestrates per-job sandbox execution.

Per-job lifecycle:
  1. Validate policy JSON
  2. Acquire slot semaphore (max 25 concurrent)
  3. Start per-job egress proxy on a Unix socket
  4. Start per-job DB proxy on a Unix socket
  5. Inject code + request via pipe FDs (bwrap --file / --ro-bind-data)
  6. Launch bwrap → python3 -S /opt/dispatcher.py
  7. Read stdout with timeout + size cap; parse __RESULT__
  8. Finally: kill proxies, SIGKILL bwrap, release semaphore
"""

import copy

import json
import logging
import os
import resource
import select
import shutil
import subprocess
import sys
import tempfile
import time
import threading
from typing import Any, Dict, Optional

# ── path setup ────────────────────────────────────────────────────────────────
_this_dir = os.path.dirname(os.path.abspath(__file__))
_root_dir  = os.path.dirname(_this_dir)
sys.path.insert(0, _root_dir)

# ── load .env if present ──────────────────────────────────────────────────────
_env_file = os.path.join(_root_dir, ".env")
if os.path.isfile(_env_file):
    with open(_env_file) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _, _v = _line.partition("=")
                os.environ.setdefault(_k.strip(), _v.strip())

from config.policy_loader import PolicyLoader
from core.sandbox_engine  import BubblewrapEngine

_engine = BubblewrapEngine()

# ── proxy script paths ────────────────────────────────────────────────────────
_EGRESS_PROXY_SCRIPT = os.path.join(_root_dir, "core", "egress_proxy.py")
_DB_PROXY_SCRIPT     = os.path.join(_root_dir, "core", "db_proxy.py")

# ── infrastructure defaults ───────────────────────────────────────────────────
N_SLOTS          = int(os.environ.get("SANDBOX_MAX_SLOTS",        "25"))
MAX_OUTPUT_BYTES = int(os.environ.get("SANDBOX_MAX_OUTPUT_BYTES", str(1 * 1024 * 1024)))
DEFAULT_TIMEOUT_S= int(os.environ.get("SANDBOX_TIMEOUT_SEC",      "30"))
MAX_WAIT_S       = int(os.environ.get("SANDBOX_MAX_WAIT_SEC",     "15"))
MAX_MEMORY_MB    = int(os.environ.get("SANDBOX_MAX_MEMORY_MB",    "512"))
MAX_FSIZE_MB     = int(os.environ.get("SANDBOX_MAX_FSIZE_MB",     "10"))
MAX_CPU_TIME     = int(os.environ.get("SANDBOX_MAX_CPU_TIME",     "10"))

# ── rlimit constants (computed once at module load) ─────────────────────────
_RLIMIT_AS    = MAX_MEMORY_MB * 1024 * 1024
_RLIMIT_FSIZE = MAX_FSIZE_MB  * 1024 * 1024
_RLIMIT_CPU   = MAX_CPU_TIME
_RLIMIT_NPROC = int(os.environ.get("SANDBOX_MAX_PIDS", "32"))  # caps fork bombs
_MAX_STDERR   = 64 * 1024

# ── logging ───────────────────────────────────────────────────────────────────
_LOG_FILE = os.path.join(_root_dir, "supervisor.log")
log = logging.getLogger("supervisor")
log.setLevel(logging.DEBUG)
if not log.handlers:
    _fh = logging.FileHandler(_LOG_FILE, encoding="utf-8")
    _fh.setLevel(logging.DEBUG)
    _sh = logging.StreamHandler()
    _sh.setLevel(logging.INFO)
    _fmt = logging.Formatter("%(asctime)s  %(levelname)-7s  %(name)s  %(message)s")
    _fh.setFormatter(_fmt)
    _sh.setFormatter(_fmt)
    log.addHandler(_fh)
    log.addHandler(_sh)

log.info("Sandbox engine: bwrap  slots=%d  timeout=%ds", N_SLOTS, DEFAULT_TIMEOUT_S)

# ── concurrency limiter ───────────────────────────────────────────────────────
slot_semaphore = threading.Semaphore(N_SLOTS)

# ── deny-all fallback policy ──────────────────────────────────────────────────
_DENY_ALL_POLICY: Dict[str, Any] = {
    "filesystem": {"allowed": []},
    "database":   {"enabled": False},
    "network":    {"enabled": False, "allowed_domains": []},
}

# ── seccomp: block process creation ──────────────────────────────────────────
# RLIMIT_NPROC cannot block fork when the container runs as root — the kernel
# exempts uid 0 (INIT_USER) unconditionally. Seccomp intercepts the syscall
# before any uid or capability check runs, so it is the correct tool here.
#
# Rule: ALLOW everything; DENY only the four syscalls that create new processes.
# clone is conditional: deny unless CLONE_THREAD is set (Python needs threads).

_CLONE_THREAD = 0x00010000  # linux/sched.h

def _compile_seccomp_bpf() -> int:
    """Compile a minimal process-creation block. Returns memfd FD or -1."""
    try:
        import seccomp
        f = seccomp.SyscallFilter(defaction=seccomp.ALLOW)
        for name in ("fork", "vfork", "clone3"):
            try:
                f.add_rule(seccomp.ERRNO(1), name)
            except Exception:
                pass  # syscall absent on this kernel
        try:
            # clone without CLONE_THREAD → new process; deny it
            f.add_rule(seccomp.ERRNO(1), "clone",
                       seccomp.Arg(0, seccomp.MASKED_EQ, _CLONE_THREAD, 0))
        except Exception:
            pass
        with tempfile.TemporaryFile() as tmp:
            f.export_bpf(tmp)
            tmp.seek(0)
            bpf = tmp.read()
        fd = os.memfd_create("seccomp-bpf", 0)
        os.write(fd, bpf)
        os.lseek(fd, 0, 0)
        log.info("Seccomp ready: fork/vfork/clone3 blocked; clone(CLONE_THREAD) allowed")
        return fd
    except ImportError:
        log.warning("python3-seccomp not installed — fork bombs not blocked by seccomp")
        return -1
    except Exception as exc:
        log.warning("Seccomp compile failed: %s", exc)
        return -1

_SECCOMP_FD_TEMPLATE = _compile_seccomp_bpf()


# ── DB driver → Unix socket filename ─────────────────────────────────────────
_SOCKET_NAMES: Dict[str, str] = {
    "postgres": ".s.PGSQL.5432", "postgresql": ".s.PGSQL.5432", "pg": ".s.PGSQL.5432",
    "mysql":    "mysql.sock",    "mariadb":    "mysql.sock",
}

# ── egress proxy ──────────────────────────────────────────────────────────────

def _start_per_job_egress_proxy(policy_file: str) -> "tuple[subprocess.Popen, str]":
    """Start per-job egress proxy on a Unix socket. Returns (process, sock_dir)."""
    sock_dir  = tempfile.mkdtemp(prefix="egress_proxy_")
    os.chmod(sock_dir, 0o755)
    sock_path = os.path.join(sock_dir, "proxy.sock")

    proc = subprocess.Popen(
        [sys.executable, _EGRESS_PROXY_SCRIPT,
         "--policy", policy_file,
         "--socket-path", sock_path,
         "--log-level", "WARNING"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    deadline = time.time() + 5.0
    while time.time() < deadline:
        if proc.poll() is not None:
            shutil.rmtree(sock_dir, ignore_errors=True)
            raise RuntimeError(
                f"Per-job egress proxy exited immediately (rc={proc.returncode})"
            )
        if os.path.exists(sock_path):
            log.info("Per-job egress proxy  PID=%d  socket=%s", proc.pid, sock_path)
            return proc, sock_dir
        time.sleep(0.1)

    proc.terminate()
    shutil.rmtree(sock_dir, ignore_errors=True)
    raise RuntimeError("Per-job egress proxy failed to become ready within 5 seconds")

# ── sandbox environment builder ───────────────────────────────────────────────

def _build_sandbox_env(
    slot_policy: dict,
    egress_sock_path: str = "",
) -> Dict[str, str]:
    """Build the env dict injected into the sandbox via bwrap --setenv.

    Security contract:
      - SANDBOX_DB_CONFIG is popped by dispatcher.py before user code starts.
        AI code receives a pre-established `db` connection object as a parameter.
      - PGHOST / MYSQL_UNIX_PORT expose only the proxy socket path (not the real
        database host, user, password, or name). Exposing the socket path is safe:
        the proxy still validates every SQL query regardless of who connects.
        These are included for backward compatibility with code that connects via
        env vars rather than the injected `db` parameter.
      - HTTP_PROXY_UNIX is popped by dispatcher.py; HTTP_PROXY is set by the bridge.
    """
    env: Dict[str, str] = {}

    db_policy  = slot_policy.get("database", {})
    net_policy = slot_policy.get("network",  {})

    if db_policy.get("enabled", False):
        conn_name = db_policy.get("connection", "primary")
        conn      = PolicyLoader.load_connection_from_env(conn_name)
        driver    = conn.get("driver", "postgres").lower()
        mount     = conn.get("sandbox_mount", "/tmp/pg")
        user      = conn.get("user",   "")
        dbname    = conn.get("dbname", "")

        # Opaque config for dispatcher.py — popped before user code starts
        env["SANDBOX_DB_CONFIG"] = json.dumps({"driver": driver, "mount": mount})

        if driver in ("postgres", "postgresql", "pg"):
            # psycopg2 reads these automatically — avoids /etc/passwd lookup
            # (which fails because /etc/passwd is not in the sandbox mount)
            env["PGHOST"]     = mount
            env["PGPORT"]     = "5432"
            env["PGUSER"]     = user
            env["PGDATABASE"] = dbname
        elif driver in ("mysql", "mariadb"):
            env["MYSQL_UNIX_PORT"] = os.path.join(mount, "mysql.sock")
            env["MYSQL_USER"]      = user
            env["MYSQL_DATABASE"]  = dbname

    # Egress proxy socket path — popped by dispatcher.py before user code
    if net_policy.get("enabled", False) and egress_sock_path:
        env["HTTP_PROXY_UNIX"] = egress_sock_path

    return env

# ── output reader (size-capped, timeout-aware) ────────────────────────────────

def _read_output(
    proc: subprocess.Popen,
    max_bytes: int,
    timeout_sec: float,
) -> "tuple[bytes, bytes, bool]":
    """Read stdout/stderr from the sandbox subprocess with a hard size cap.

    Returns (stdout_bytes, stderr_bytes, truncated).
    Kills the process on timeout.
    """
    stdout_chunks: list = []
    stderr_chunks: list = []
    stderr_total = 0
    total     = 0
    truncated = False
    deadline  = time.time() + timeout_sec

    fds = []
    if proc.stdout:
        fds.append(proc.stdout)
    if proc.stderr:
        fds.append(proc.stderr)

    while fds:
        remaining = deadline - time.time()
        if remaining <= 0:
            proc.kill()
            break
        try:
            ready, _, _ = select.select(fds, [], [], min(remaining, 0.5))
        except (ValueError, OSError):
            break

        if not ready:
            if proc.poll() is not None:
                break
            continue

        for fd in ready:
            try:
                chunk = os.read(fd.fileno(), 65536)
            except OSError:
                fds.remove(fd)
                continue
            if not chunk:
                fds.remove(fd)
                continue
            if fd is proc.stdout:
                if not truncated:
                    available = max_bytes - total
                    if len(chunk) > available:
                        stdout_chunks.append(chunk[:available])
                        truncated = True
                    else:
                        stdout_chunks.append(chunk)
                        total += len(chunk)
                # Always drain even when truncated so the sandbox doesn't block
            else:
                if stderr_total < _MAX_STDERR:
                    stderr_chunks.append(chunk)
                    stderr_total += len(chunk)

    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()

    return b"".join(stdout_chunks), b"".join(stderr_chunks), truncated

# ── cgroup pids.max — per-job fork-bomb protection ────────────────────────────
# RLIMIT_NPROC is bypassed when uid 0 has CAP_SYS_RESOURCE inside a user
# namespace. cgroup pids.max is enforced by the kernel unconditionally —
# no capability exempts it.

def _apply_pids_cgroup(pid: int) -> Optional[str]:
    """
    Place `pid` in a fresh per-job cgroup with pids.max = _RLIMIT_NPROC.
    Tries cgroupv2 (unified) then cgroupv1 (pids controller).
    Returns the cgroup path on success, None if cgroups are not available.
    Failure is non-fatal — other bwrap isolation layers still apply.
    """
    tag = f"bwrap_{pid}"
    for base, procs_file in [
        ("/sys/fs/cgroup",       "cgroup.procs"),   # cgroupv2 unified hierarchy
        ("/sys/fs/cgroup/pids",  "tasks"),           # cgroupv1 pids controller
    ]:
        cg = os.path.join(base, tag)
        try:
            os.makedirs(cg, exist_ok=True)
            max_path = os.path.join(cg, "pids.max")
            if not os.path.exists(max_path):
                os.rmdir(cg)
                continue
            open(max_path,                     "w").write(str(_RLIMIT_NPROC))
            open(os.path.join(cg, procs_file), "w").write(str(pid))
            log.info("Cgroup pids.max=%d  path=%s", _RLIMIT_NPROC, cg)
            return cg
        except OSError:
            try:
                os.rmdir(cg)
            except OSError:
                pass
    log.warning("Cgroup pids limit unavailable — fork-bomb protection via rlimit only")
    return None


def _remove_pids_cgroup(cg: str) -> None:
    """Remove the per-job cgroup created by _apply_pids_cgroup."""
    try:
        os.rmdir(cg)
    except OSError:
        pass


# ── main request handler ──────────────────────────────────────────────────────

def handle_request(
    code:                str,
    rpc_request:         str,
    timeout_ms:          int  = int(DEFAULT_TIMEOUT_S * 1000),
    max_out_bytes:       int  = MAX_OUTPUT_BYTES,
    dynamic_policy_json: Optional[str] = None,
) -> bytes:
    """Execute `code` inside the sandbox and return raw JSON response bytes."""
    if not slot_semaphore.acquire(timeout=MAX_WAIT_S):
        return json.dumps({
            "error": "Server overloaded — no slot available. Try again later.",
            "exit_code": -1, "stdout": "", "stderr": "", "truncated": False, "wall_ms": 0,
        }).encode()

    # Parse per-request policy
    if dynamic_policy_json:
        try:
            slot_policy = json.loads(dynamic_policy_json)
        except Exception as exc:
            slot_semaphore.release()
            return json.dumps({
                "error": f"Invalid policy JSON: {exc}",
                "exit_code": -1, "stdout": "", "stderr": "", "truncated": False, "wall_ms": 0,
            }).encode()
    else:
        slot_policy = copy.deepcopy(_DENY_ALL_POLICY)

    # Per-job handles — all initialised so finally block is always safe
    dynamic_policy_file:  Optional[str]             = None
    task_egress_proc:     Optional[subprocess.Popen] = None
    task_egress_sock_dir: Optional[str]             = None
    task_db_proc:         Optional[subprocess.Popen] = None
    task_db_socket_dir:   Optional[str]             = None
    job_cgroup:           Optional[str]             = None
    proc:                 Optional[subprocess.Popen] = None
    args_fd:              int                        = -1
    seccomp_fd:           int                        = -1
    code_fd:              int                        = -1
    req_fd:               int                        = -1
    start_time                                       = time.time()

    try:
        policy_fd, dynamic_policy_file = tempfile.mkstemp(suffix=".json", prefix="policy_")
        with os.fdopen(policy_fd, "w") as pf:
            pf.write(dynamic_policy_json or json.dumps(_DENY_ALL_POLICY))

        db_cfg  = slot_policy.get("database",   {})
        net_cfg = slot_policy.get("network",    {})
        fs_cfg  = slot_policy.get("filesystem", {})

        try:
            _rpc = json.loads(rpc_request)
            rpc_label = f"{_rpc.get('class_name','')}.{_rpc.get('function','?')}()".lstrip(".")
        except Exception:
            rpc_label = "?"

        log.info("══════════════════════════════════════════════")
        log.info("TASK START  rpc=%s", rpc_label)
        log.info("Policy  fs_rules=%d  db=%-3s  net=%s",
                 len(fs_cfg.get("allowed", [])),
                 ("ON" if db_cfg.get("enabled") else "OFF"),
                 ("ON  domains=" + str([d.get("domain") for d in net_cfg.get("allowed_domains", [])])
                  if net_cfg.get("enabled") else "OFF"))

        # Start per-job egress proxy (Unix socket)
        egress_sock_path = ""
        if net_cfg.get("enabled", False):
            task_egress_proc, task_egress_sock_dir = _start_per_job_egress_proxy(
                dynamic_policy_file
            )
            egress_sock_path = os.path.join(task_egress_sock_dir, "proxy.sock")

        # Start per-job DB proxy
        db_mount = ""
        if db_cfg.get("enabled", False):
            conn_name   = db_cfg.get("connection", "primary")
            conn        = PolicyLoader.load_connection_from_env(conn_name)
            driver_name = conn.get("driver", "postgres").lower()
            if driver_name not in _SOCKET_NAMES:
                raise ValueError(f"Unsupported DB driver: {driver_name!r}")
            db_mount = conn.get("sandbox_mount", "/tmp/pg")
            os.makedirs(db_mount, exist_ok=True)

            task_db_socket_dir = tempfile.mkdtemp(prefix="db_proxy_")
            os.chmod(task_db_socket_dir, 0o755)

            # Open proxy.log once — write header, pass fd to Popen, close our copy
            _proxy_log = open(os.path.join(_root_dir, "proxy.log"), "a")
            _proxy_log.write(f"\n--- DB Proxy [{driver_name}] ---\n")
            _proxy_log.flush()
            task_db_proc = subprocess.Popen(
                [sys.executable, _DB_PROXY_SCRIPT,
                 "--policy", dynamic_policy_file,
                 "--sandbox-mount", task_db_socket_dir],
                stdout=_proxy_log,
                stderr=subprocess.STDOUT,
            )
            _proxy_log.close()  # child inherited the fd; parent no longer needs it

            proxy_socket = os.path.join(task_db_socket_dir, _SOCKET_NAMES[driver_name])
            for _ in range(50):
                if os.path.exists(proxy_socket):
                    break
                if task_db_proc.poll() is not None:
                    raise RuntimeError('Per-job DB proxy failed to start.')
                time.sleep(0.1)
            else:
                raise RuntimeError('Per-job DB proxy socket did not appear within timeout')
            log.info("Per-job DB proxy  driver=%-8s  PID=%d  socket=%s",
                     driver_name, task_db_proc.pid, proxy_socket)

        # Inject code and request via pipe FDs (bwrap --file / --ro-bind-data)
        code_fd = os.memfd_create('sandbox-code', 0)
        os.write(code_fd, code.encode('utf-8'))
        os.lseek(code_fd, 0, 0)

        req_fd = os.memfd_create('sandbox-req', 0)
        os.write(req_fd, rpc_request.encode('utf-8'))
        os.lseek(req_fd, 0, 0)

        # Dup seccomp BPF FD for this job
        if _SECCOMP_FD_TEMPLATE >= 0:
            seccomp_fd = os.dup(_SECCOMP_FD_TEMPLATE)
            os.lseek(seccomp_fd, 0, 0)

        # Build sandbox env and bwrap command
        sandbox_env = _build_sandbox_env(slot_policy, egress_sock_path)
        job = {
            "code_fd":         code_fd,
            "req_fd":          req_fd,
            "seccomp_fd":      seccomp_fd,
            "egress_sock_dir": task_egress_sock_dir or "",
            "env":             sandbox_env,
        }
        argv = _engine.build_command(slot_policy, job)

        # DB socket bind-mount (appended before final command)
        if task_db_socket_dir and db_mount:
            argv.extend(["--bind", task_db_socket_dir, db_mount])

        # Final command — python3 directly (no exec_harness)
        argv.extend(["python3", "-S", "/opt/dispatcher.py"])

        # argfd transport — hides policy paths from /proc/PID/cmdline.
        # This is a system security setting, not per-task — read from env.
        want_argfd = os.environ.get("SANDBOX_ARGFD_TRANSPORT", "1").lower() in ("1", "true", "yes")
        if want_argfd:
            inner = argv[1:]
            blob  = b"\0".join(a.encode() for a in inner) + b"\0"
            try:
                args_fd = os.memfd_create("bwrap-args", 0)
                os.write(args_fd, blob)
                os.lseek(args_fd, 0, 0)
            except (AttributeError, OSError):
                if len(blob) < 60 * 1024:
                    r, w = os.pipe()
                    os.write(w, blob)
                    os.close(w)
                    args_fd = r
                else:
                    log.warning("argfd blob too large; falling back to plain argv")
            if args_fd >= 0:
                argv = ["bwrap", "--args", str(args_fd),
                        "python3", "-S", "/opt/dispatcher.py"]

        # rlimits applied in preexec (no setuid — iptables gone, uid targeting not needed)
        def _preexec() -> None:
            try:
                resource.setrlimit(resource.RLIMIT_AS,    (_RLIMIT_AS,    _RLIMIT_AS))
                resource.setrlimit(resource.RLIMIT_FSIZE, (_RLIMIT_FSIZE, _RLIMIT_FSIZE))
                resource.setrlimit(resource.RLIMIT_CPU,   (_RLIMIT_CPU,   _RLIMIT_CPU))
                resource.setrlimit(resource.RLIMIT_NPROC, (_RLIMIT_NPROC, _RLIMIT_NPROC))
            except (ValueError, OSError):
                os.write(2, b'supervisor: could not set rlimits\n')

        pass_fds = [fd for fd in (code_fd, req_fd, seccomp_fd, args_fd) if fd >= 0]

        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=_preexec,
            pass_fds=tuple(pass_fds),
        )
        job_cgroup = _apply_pids_cgroup(proc.pid)
        # Close our copies of the injected FDs — bwrap has them now
        for fd in (code_fd, req_fd, seccomp_fd, args_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
        code_fd = req_fd = seccomp_fd = args_fd = -1

        # Read output with timeout and size cap
        stdout_bytes, stderr_bytes, truncated = _read_output(
            proc, max_out_bytes, (timeout_ms / 1000) + 5
        )

        wall_ms   = int((time.time() - start_time) * 1000)
        exit_code = proc.returncode if proc.returncode is not None else -1

        # Parse __RESULT__: prefix
        result       = None
        stdout_lines = []
        for line in stdout_bytes.decode("utf-8", errors="replace").splitlines():
            if line.startswith("__RESULT__:"):
                result = line[len("__RESULT__:"):]
            else:
                stdout_lines.append(line)

        log.info("TASK END  exit=%-3s  wall=%dms  truncated=%s",
                 exit_code, wall_ms, truncated)
        log.info("══════════════════════════════════════════════")

        return json.dumps({
            "exit_code": exit_code,
            "stdout":    "\n".join(stdout_lines),
            "stderr":    stderr_bytes.decode("utf-8", errors="replace")[-2000:],
            "truncated": truncated,
            "result":    result,
            "wall_ms":   wall_ms,
        }).encode()

    except Exception as exc:
        wall_ms = int((time.time() - start_time) * 1000)
        log.error("TASK ERROR  wall=%dms  error=%s", wall_ms, exc)
        log.info("══════════════════════════════════════════════")
        return json.dumps({
            "error": str(exc), "exit_code": -1, "stdout": "", "stderr": "",
            "truncated": False, "wall_ms": wall_ms,
        }).encode()

    finally:
        # Kill egress proxy and clean up its socket dir
        if task_egress_proc is not None:
            task_egress_proc.terminate()
            try:
                task_egress_proc.wait(timeout=2)
            except Exception:
                task_egress_proc.kill()
        if task_egress_sock_dir and os.path.exists(task_egress_sock_dir):
            shutil.rmtree(task_egress_sock_dir, ignore_errors=True)

        # Kill DB proxy and clean up its socket dir
        if task_db_proc is not None:
            task_db_proc.terminate()
            try:
                task_db_proc.wait(timeout=2)
            except Exception:
                task_db_proc.kill()
        if task_db_socket_dir and os.path.exists(task_db_socket_dir):
            shutil.rmtree(task_db_socket_dir, ignore_errors=True)

        # Remove policy temp file
        if dynamic_policy_file and os.path.exists(dynamic_policy_file):
            os.remove(dynamic_policy_file)

        # Remove per-job pids cgroup
        if job_cgroup:
            _remove_pids_cgroup(job_cgroup)
        # Kill bwrap
        if proc is not None:
            try:
                proc.kill()
            except OSError:
                pass
            try:
                proc.wait(timeout=2)
            except Exception:
                pass

        # Close any FDs we still hold
        for fd in (code_fd, req_fd, seccomp_fd, args_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass

        slot_semaphore.release()
