# 🛡️ Advanced AI-Generated Python Sandbox

This project implements a sophisticated sandbox for running arbitrary Python code safely using Linux kernel features:
- **Namespaces** (user, mount, UTS, IPC, PID, network) via bubblewrap
- **Seccomp-BPF filter** to restrict system calls
- **Landlock LSM** for filesystem access control
- **Cgroups v2** for resource limiting
- **Privilege dropping** to unprivileged user
- **Pre-warmed slot pool** for performance

## 📁 Files

| File | Purpose |
|------|---------|
| `Dockerfile` | Builds the sandbox image with all necessary tools |
| `supervisor.py` | Manages slot pool, handles HTTP requests, orchestrates sandboxing |
| `exec_harness.c` | Trusted helper that runs inside the sandbox, drops privileges, applies Landlock, runs user code |
| `seccomp_allow.txt` | Syscall allow-list for seccomp filter |
| `landlock_ruleset.json` | Filesystem access rules for Landlock |
| `run_sandbox.sh` | Container entrypoint that loads configuration and starts supervisor |
| `test_sandbox_runner.py` | Test client demonstrating usage |
| `requirements.txt` | Python dependencies for test client |

## 🔧 How the Sandbox Works

1. **Request Handling** - Supervisor receives HTTP POST request with Python code to execute
2. **Slot Acquisition** - Acquires a pre-warmed slot from the pool (or waits if none available)
3. **Sandbox Setup** - Uses bubblewrap to create isolated namespaces:
   - User namespace: Maps root to unprivileged UID/GID
   - Mount namespace: Restricts filesystem view
   - UTS/IPC/PID/Network namespaces: Isolates hostname, IPC, processes, network
4. **Security Layers** (applied before user code runs):
   - Seccomp-BPF filter: Only allows safe syscalls for Python I/O
   - Landlock LSM: Restricts filesystem access to `/tmp`, `/sandbox`, `/input`, `/output`
   - Cgroups v2: Limits memory (~128 MiB), CPU (~20% core), processes (≤20)
   - Privilege dropping: Runs as UID/GID 65534 (nobody), drops all capabilities
5. **Execution** - Exec_harness runs inside the sandbox:
   - Drops additional privileges
   - Applies Landlock rules (if kernel supports it)
   - Forks to run `python3 /sandbox/code.py`
   - Captures stdout/stderr via pipe, enforces size limits
   - Returns JSON result via UNIX domain socket
6. **Result Processing** - Supervisor collects result, releases slot, returns HTTP response

## ▶️ Prerequisites

1. **Docker Desktop** installed and running (using WSL2 backend)
2. **Python 3.8+** on host (for test client only)

## 🛠️ Setup and Usage

### Option 1: Using helper script (Recommended)
```powershell
# Build and run the sandbox
docker build -t advanced-python-sandbox advanced-sandbox
docker run -p 8080:8080 --name sandbox advanced-python-sandbox

# In another PowerShell window, install test dependencies and run tests
pip install -r advanced-sandbox/requirements.txt
python advanced-sandbox/test_f1.py
```

### Option 2: Manual steps
```powershell
# 1️⃣ Build the sandbox image
docker build -t advanced-python-sandbox advanced-sandbox

# 2️⃣ Run the sandbox container (this will start the supervisor)
docker run -d -p 8080:8080 --name sandbox advanced-python-sandbox

# 3️⃣ Install test client dependencies
pip install -r advanced-sandbox/requirements.txt

# 4️⃣ Run the test client
python advanced-sandbox/test_f1.py
```

### Expected Output
You should see results similar to:
```
Testing sandbox runner with simple code...
Result: {
  "exit_code": 0,
  "stdout": "4",
  "stderr": "",
  "truncated": false,
  "wall_ms": 125,
  "error": ""
}

Testing sandbox runner with code without a helper...
Result: {
  "exit_code": 0,
  "stdout": "Hello, World!",
  "stderr": "",
  "truncated": false,
  "wall_ms": 98,
  "error": ""
}

Testing sandbox runner with potentially unsafe code...
Result: {
  "exit_code": -1,
  "stdout": "",
  "stderr": "",
  "truncated": false,
  "wall_ms": 152,
  "error": "..."  // Error from seccomp/Landlock blocking the operation
}
```

## ⚠️ Notes

- This sandbox is designed for **educational purposes** and **low-risk experimentation**
- While it provides strong isolation using multiple Linux security layers, it still shares the host kernel
- For **maximum security** against kernel exploits, consider VM-based sandboxes (Firecracker, gVisor)
- The sandbox blocks common escape routes:
  - No filesystem access outside allowed directories (Landlock)
  - No new processes (seccomp blocks fork/clone)
  - No network access (network namespace)
  - No privilege escalation (dropped capabilities, no-new-privileges)
  - Resource limits prevent DoS via memory/CPU exhaustion

## 🧹 Cleaning Up

```powershell
docker stop sandbox
docker rm sandbox
docker rmi advanced-python-sandbox
```