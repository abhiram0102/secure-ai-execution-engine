# Enterprise AI Sandbox Core (`advanced-sandbox/`)

This directory contains the highly privileged components of the **Zero-Trust AI Sandbox**. 

These files are responsible for constructing the ephemeral Bubblewrap container, dropping Linux privileges, applying Landlock/Seccomp kernel filters, and securely routing the Python execution.

## 📁 Files

| File | Purpose |
|------|---------|
| `supervisor.py` | The Warden. Constructs the Bubblewrap (`bwrap`) container boundaries and manages UNIX socket pipelines. |
| `exec_harness.c` | The Security Lock. A compiled C binary that runs *inside* the container to drop capabilities and freeze the kernel before giving way to Python. |
| `dispatcher.py` | The Brain. The restricted Python script that reconstructs stateful objects and executes the untrusted AI code. |
| `seccomp_allow.txt` | The strict whitelist of allowed CPU instructions. |
| `landlock_ruleset.json` | The strict whitelist of filesystem paths. |

## ⚠️ Security Notes
This architecture is designed for **Enterprise Production** environments.
It employs a Defense-in-Depth strategy combining:
- **Bubblewrap**: Network, IPC, and PID isolation.
- **Capabilities**: Unprivileged execution and capability annihilation.
- **Landlock**: Permanent filesystem freezing.
- **Seccomp**: Execution prevention (`fork`/`clone` blocking) to prevent reverse shells.

For the complete architectural design and threat models, please read the `System_Architecture_Documentation.md` file located at the root of the repository.