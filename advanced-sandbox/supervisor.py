#!/usr/bin/env python3
# supervisor.py for advanced sandbox
"""
Advanced sandbox supervisor using bubblewrap, namespaces, seccomp, Landlock, cgroups.
"""

print("DEBUG: supervisor.py starting...", flush=True)

import json
import os
import socket
import struct
import subprocess
import tempfile
import threading
import time
from http.server import HTTPServer, ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
import shutil

# Configuration
N_SLOTS = 25  # Number of pre-warmed slots
MAX_OUTPUT_BYTES = 1 * 1024 * 1024  # 1 MiB
DEFAULT_TIMEOUT_SEC = 5

# Load resources from environment (set by run_sandbox.sh)
LANDLOCK_BLOB = os.environ.get('LANDLOCK_BLOB', '').encode('latin-1')

# Mount arguments for bubblewrap (from response.md)
MOUNT_ARGS = [
    "--ro-bind", "/usr", "/usr",
    "--ro-bind", "/lib", "/lib",
    "--ro-bind", "/lib64", "/lib64",
    "--ro-bind", "/bin", "/bin",
    "--ro-bind", "/sbin", "/sbin",
    "--tmpfs", "/tmp",
    "--proc", "/proc",
    "--dev", "/dev",
]

# CGroups v2 template path (would be set up in container)
CGROUP_TEMPLATE = "/sys/fs/cgroup/exec/template"

# Slot management (Concurrency Limiter)
# We use a Semaphore so that overflow requests wait in a queue instead of instantly failing.
slot_semaphore = threading.Semaphore(N_SLOTS)

def recv_exact(sock, n):
    """Receive exactly n bytes from socket."""
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b''
        buf += chunk
    return buf

def handle_request(code, rpc_request, timeout_ms=5000, max_out_bytes=MAX_OUTPUT_BYTES, extra_mounts=None):
    """Handle a single sandbox request."""
    print(f"DEBUG: handle_request called, code length {len(code)}", flush=True)
    
    # Block and wait in a queue for an available slot (up to 15 seconds)
    if not slot_semaphore.acquire(timeout=15.0):
        return json.dumps({
            "error": "Server overloaded. Request timed out waiting for an execution slot.",
            "exit_code": -1,
            "stdout": "",
            "stderr": "",
            "truncated": False,
            "wall_ms": 0
        }).encode()

    start_time = time.time()
    proc = None
    parent_sock = None
    child_sock = None
    try:
        # Create temporary directory for this job
        job_id = f"job_{int(time.time()*1e6)}_{os.getpid()}"
        base = f"/tmp/sandbox_exec/{job_id}"
        os.makedirs(f"{base}/out", exist_ok=True)
        os.makedirs(f"{base}/sandbox", exist_ok=True)

        # Write the exact code passed by main_app.py (No wrappers!)
        with open(f"{base}/sandbox/ai_code_sandbox.py", "wb") as f:
            f.write(code.encode('utf-8'))
            
        # Write the JSON RPC request
        with open(f"{base}/sandbox/request.json", "wb") as f:
            f.write(rpc_request.encode('utf-8'))

        # Create socket pair for supervisor-exec_harness communication
        # pyrefly: ignore [missing-attribute]
        parent_sock, child_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

        # Enable peer credentials checking
        # pyrefly: ignore [missing-attribute]
        parent_sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        # pyrefly: ignore [missing-attribute]
        child_sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)

        # Build bubblewrap command
        argv = ["bwrap",
                "--new-session", "--unshare-all", "--die-with-parent",
        ]

        # Seccomp is now handled natively inside exec_harness.c via libseccomp!
        # We no longer pass an external blob to bwrap.

        # Add Landlock if we have a blob (requires new session)
        if LANDLOCK_BLOB:
            argv.append("--new-session")
            print(f"DEBUG: Adding Landlock, blob length {len(LANDLOCK_BLOB)}", flush=True)
        else:
            print("DEBUG: No Landlock blob", flush=True)

        argv.extend(MOUNT_ARGS + [
                "--chdir", "/sandbox",
                "--setenv", "PATH", "/usr/bin:/bin",
                "--setenv", "SOCKET_FD", str(child_sock.fileno()),
        ])

        # Add Landlock blob via environment if needed
        env = os.environ.copy()
        if LANDLOCK_BLOB:
            env["LANDLOCK_BLOB"] = LANDLOCK_BLOB.decode('latin-1')
            print("DEBUG: Setting LANDLOCK_BLOB env", flush=True)

        # Add sandboxed directories via environment
        env["SANDBOX_PATH"] = "/sandbox"
        env["OUTPUT_PATH"] = "/output"

        # Add bind mounts for sandbox, and output directories
        argv.extend(["--ro-bind", f"{base}/sandbox", "/sandbox",
                     "--bind", f"{base}/out", "/output",
                     "--ro-bind", "/opt", "/opt"])

        if extra_mounts:
            for host_path, sandbox_path in extra_mounts.items():
                argv.extend(["--ro-bind", host_path, sandbox_path])

        # Start bubblewrap process
        # Determine which fds to pass: child_sock always
        pass_fds = [child_sock.fileno()]
        
        proc = subprocess.Popen(
            argv + ["/opt/exec_harness"],
            env=env,
            pass_fds=pass_fds,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        # Parent closes child-side fd immediately
        child_sock.close()

        # Send request to exec_harness via UNIX socket
        request_data = json.dumps({
            "code": code,
            "timeout_ms": timeout_ms,
            "max_out_bytes": max_out_bytes
        }).encode()

        parent_sock.sendall(struct.pack(">I", len(request_data)) + request_data)

        # Receive response with timeout
        parent_sock.settimeout((timeout_ms + 1000) / 1000.0)  # Add 1s slack
        resp_len_data = recv_exact(parent_sock, 4)
        if not resp_len_data:
            raise TimeoutError("No response from exec_harness")

        resp_len = struct.unpack(">I", resp_len_data)[0]
        resp_data = recv_exact(parent_sock, resp_len)

        return resp_data

    except Exception as e:
        print(f"DEBUG: Exception in handle_request: {e}", flush=True)
        return json.dumps({
            "error": str(e),
            "exit_code": -1,
            "stdout": "",
            "stderr": "",
            "truncated": False,
            "wall_ms": int((time.time() - start_time) * 1000)
        }).encode()
    finally:
        if proc is not None:
            proc.kill()
            stdout, stderr = proc.communicate()
            print(f"DEBUG: bwrap process exited with code {proc.returncode}", flush=True)
            print(f"DEBUG: bwrap stdout: {stdout}", flush=True)
            print(f"DEBUG: bwrap stderr: {stderr}", flush=True)
        if parent_sock is not None:
            parent_sock.close()
        if child_sock is not None:
            child_sock.close()
        slot_semaphore.release()

