#!/usr/bin/env bash
# run_production.sh — entry point for the production container.

set -euo pipefail

# ── SIGTERM / SIGINT trap — clean shutdown for docker stop ────────────────────
trap 'kill $(jobs -p) 2>/dev/null; exit 0' SIGTERM SIGINT

# ── load .env if present ──────────────────────────────────────────────────────
if [ -f /app/.env ]; then
    set -a
    # shellcheck source=/dev/null
    source /app/.env
    set +a
    echo "[startup] Loaded /app/.env"
fi

export SANDBOX_POLICY="${SANDBOX_POLICY:-/app/config/sandbox_policy.json}"
echo "[startup] Using policy: ${SANDBOX_POLICY}"

# ── validate policy before doing anything else ────────────────────────────────
python3 /app/config/policy_loader.py "${SANDBOX_POLICY}"

# ── F10: bootstrap local CA (idempotent — no-op after first run) ─────────────
if [ -x /app/scripts/bootstrap_local_ca.sh ]; then
    /app/scripts/bootstrap_local_ca.sh || {
        echo "[startup] WARNING: local CA bootstrap failed; DB-proxy TLS may fall back to plaintext."
    }
fi

# ── helper: read a value from the policy JSON ─────────────────────────────────
policy_get() {
    # usage: policy_get '.database.enabled'
    # Policy path is passed as argv[1] to avoid shell-injection via variable interpolation
    python3 -c "
import json, sys
with open(sys.argv[1]) as f:
    p = json.load(f)
keys = sys.argv[2].lstrip('.').split('.')
v = p
for k in keys:
    if k.isdigit():
        v = v[int(k)]
    else:
        v = v.get(k, '')
print(v)
" "${SANDBOX_POLICY}" "$1" 2>/dev/null || echo ""
}

# ── database: DB proxy is per-job — no container-wide daemon needed ───────────
DB_ENABLED=$(policy_get '.database.enabled')
if [ "${DB_ENABLED}" = "True" ] || [ "${DB_ENABLED}" = "true" ]; then
    echo "[startup] Database access is enabled — per-job DB proxies will be managed by supervisor."
else
    echo "[startup] Database access is disabled in policy."
fi

# ── network: egress proxy is per-job — no container-wide daemon needed ────────
NET_ENABLED=$(policy_get '.network.enabled')
if [ "${NET_ENABLED}" = "True" ] || [ "${NET_ENABLED}" = "true" ]; then
    echo "[startup] Network egress is enabled — per-job egress proxies will be managed by supervisor."
else
    echo "[startup] Network egress is disabled in policy."
fi

# ── keep container alive ──────────────────────────────────────────────────────
echo "[startup] Container is fully initialized."
echo "    docker exec -it sandbox-daemon bash"
tail -f /dev/null &
wait
