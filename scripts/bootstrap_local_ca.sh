#!/usr/bin/env bash
# bootstrap_local_ca.sh
#
# F10 — bootstrap a self-signed CA + leaf certificates for the trusted-plane
# components (DB proxy client, egress proxy, and — optionally — the Postgres
# server if we manage it in-cluster).
#
# Idempotent: files under $CA_DIR are only created if missing. Safe to run
# on every container start from run_production.sh.
#
# Layout produced at $CA_DIR (default /etc/sandbox/certs):
#   ca.key                  4096-bit RSA CA private key       (root:root 0400)
#   ca.crt                  10-year CA certificate            (root:root 0444)
#   dbproxy-client.key      DB proxy client TLS key           (root:root 0400)
#   dbproxy-client.crt      DB proxy client TLS cert          (root:root 0444)
#   pg-server.key           optional Postgres server key      (root:root 0400)
#   pg-server.crt           optional Postgres server cert     (root:root 0444)
#
# The paths above are what config/sandbox_policy.json references via
# database.connections[].upstream_ssl_{ca,client_cert,client_key}_path.
#
# NOTE: this is deliberately a single-host, self-signed local CA — no
# cert rotation drift, no external dependencies. For multi-host / federated
# deployments, replace this script with your PKI of choice (SPIFFE, cert-manager,
# HashiCorp Vault PKI, AWS ACM Private CA) and keep the SAME output paths so
# the policy JSON does not need to change.

set -euo pipefail

CA_DIR="${SANDBOX_CA_DIR:-/etc/sandbox/certs}"
CA_CN="${SANDBOX_CA_CN:-Bubble-Wrap Local CA}"
DBPROXY_CN="${SANDBOX_DBPROXY_CN:-dbproxy.sandbox.local}"
PGSERVER_CN="${SANDBOX_PG_CN:-pg-primary.sandbox.local}"
DAYS_CA="${SANDBOX_CA_DAYS:-3650}"
DAYS_LEAF="${SANDBOX_LEAF_DAYS:-825}"   # <= 825 days per public-CA browser rules
KEY_BITS="${SANDBOX_KEY_BITS:-4096}"

mkdir -p "$CA_DIR"
chmod 0755 "$CA_DIR"

log() { echo "[bootstrap_local_ca] $*"; }

# ────────────────────────────────────────────────────────────────────────────
# 1. Root CA — generated once, kept forever
# ────────────────────────────────────────────────────────────────────────────
if [[ ! -s "$CA_DIR/ca.key" || ! -s "$CA_DIR/ca.crt" ]]; then
    log "generating fresh CA (CN=$CA_CN, ${DAYS_CA}d, ${KEY_BITS} bit)"
    openssl genrsa -out "$CA_DIR/ca.key" "$KEY_BITS" 2>/dev/null
    openssl req -x509 -new -nodes \
        -key "$CA_DIR/ca.key" \
        -sha256 -days "$DAYS_CA" \
        -subj "/CN=$CA_CN" \
        -out "$CA_DIR/ca.crt"
else
    log "CA already present, not regenerating"
fi

chmod 0400 "$CA_DIR/ca.key"
chmod 0444 "$CA_DIR/ca.crt"

# ────────────────────────────────────────────────────────────────────────────
# 2. Leaf issuance helper
# ────────────────────────────────────────────────────────────────────────────
issue_leaf() {
    local name="$1"   # filename prefix, e.g. "dbproxy-client"
    local cn="$2"     # subject CN
    local san="$3"    # subjectAltName block ("DNS:foo,DNS:bar,IP:1.2.3.4")
    local eku="$4"    # extendedKeyUsage ("clientAuth" or "serverAuth")

    local key="$CA_DIR/$name.key"
    local crt="$CA_DIR/$name.crt"

    if [[ -s "$key" && -s "$crt" ]]; then
        # Skip if the existing cert is not expiring within 30 days
        if openssl x509 -in "$crt" -noout -checkend $((30*86400)) >/dev/null 2>&1; then
            log "leaf '$name' present and healthy, skipping"
            chmod 0400 "$key"; chmod 0444 "$crt"
            return 0
        fi
        log "leaf '$name' expiring soon, re-issuing"
    else
        log "issuing leaf '$name' (CN=$cn, ${DAYS_LEAF}d, EKU=$eku)"
    fi

    local tmp
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN

    openssl genrsa -out "$key" "$KEY_BITS" 2>/dev/null

    cat > "$tmp/csr.cnf" <<EOF
[req]
distinguished_name = dn
req_extensions     = req_ext
prompt             = no
[dn]
CN = $cn
[req_ext]
subjectAltName = $san
EOF

    cat > "$tmp/ext.cnf" <<EOF
subjectAltName        = $san
extendedKeyUsage      = $eku
basicConstraints      = critical, CA:FALSE
keyUsage              = critical, digitalSignature, keyEncipherment
subjectKeyIdentifier  = hash
authorityKeyIdentifier= keyid,issuer
EOF

    openssl req -new -key "$key" -out "$tmp/csr.pem" -config "$tmp/csr.cnf"
    openssl x509 -req -in "$tmp/csr.pem" \
        -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" -CAcreateserial \
        -out "$crt" -days "$DAYS_LEAF" -sha256 \
        -extfile "$tmp/ext.cnf" 2>/dev/null

    chmod 0400 "$key"
    chmod 0444 "$crt"
}

# ────────────────────────────────────────────────────────────────────────────
# 3. Issue the trusted-plane leaves
# ────────────────────────────────────────────────────────────────────────────
issue_leaf "dbproxy-client" "$DBPROXY_CN" \
    "DNS:${DBPROXY_CN}" \
    "clientAuth"

# Only issue a Postgres server cert when explicitly opted-in — most production
# deployments use a Postgres server managed elsewhere with its own PKI.
if [[ "${SANDBOX_ISSUE_PG_SERVER_CERT:-0}" = "1" ]]; then
    issue_leaf "pg-server" "$PGSERVER_CN" \
        "DNS:${PGSERVER_CN},DNS:localhost,IP:127.0.0.1" \
        "serverAuth"
fi

# ────────────────────────────────────────────────────────────────────────────
# 4. Emit a JSON summary the policy can `include:` or the operator can eyeball
# ────────────────────────────────────────────────────────────────────────────
cat > "$CA_DIR/SUMMARY.json" <<EOF
{
    "ca_dir":                        "$CA_DIR",
    "ca_cert":                       "$CA_DIR/ca.crt",
    "dbproxy_client_cert":           "$CA_DIR/dbproxy-client.crt",
    "dbproxy_client_key":            "$CA_DIR/dbproxy-client.key",
    "pg_server_cert":                "$CA_DIR/pg-server.crt",
    "pg_server_key":                 "$CA_DIR/pg-server.key",
    "pg_server_cn":                  "$PGSERVER_CN"
}
EOF
chmod 0444 "$CA_DIR/SUMMARY.json"

log "trusted-plane certificate material ready under $CA_DIR"
