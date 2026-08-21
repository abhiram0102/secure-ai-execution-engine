"""
policy_loader.py
Loads, validates, and exposes sandbox_policy.json.
Every other component imports this — nothing else parses the policy file.
"""

import json
import os
import jsonschema
from typing import Any, Dict, List


def _parse_port(env_key: str, default: str) -> int:
    """Read an integer port from environment; raise PolicyValidationError on bad value."""
    raw = os.environ.get(env_key, default) or default
    try:
        return int(raw)
    except ValueError:
        raise PolicyValidationError(
            f"Environment variable {env_key!r} must be an integer port number, got {raw!r}"
        )


class PolicyValidationError(Exception):
    """Raised when the policy file has an invalid value or missing field."""


class PolicyLoader:
    """
    Loads and validates sandbox_policy.json.

    Usage:
        loader = PolicyLoader("/app/config/sandbox_policy.json")
        policy = loader.load()   # raises PolicyValidationError on bad config
    """

    def __init__(self, policy_path: str):
        self.policy_path = policy_path
        self.schema_path = os.path.join(os.path.dirname(__file__), "sandbox_policy.schema.json")

    def load(self) -> Dict[str, Any]:
        if not os.path.exists(self.policy_path):
            raise PolicyValidationError(f"Policy file not found: {self.policy_path}")

        with open(self.policy_path, "r", encoding="utf-8") as fh:
            try:
                # json.load handles comments-as-keys fine since JSON doesn't
                # allow real comments — our _comment keys are just ignored data.
                policy = json.load(fh)
            except json.JSONDecodeError as exc:
                raise PolicyValidationError(f"Policy file is not valid JSON: {exc}") from exc

        if not os.path.exists(self.schema_path):
            raise PolicyValidationError(f"Schema file not found: {self.schema_path}")
            
        with open(self.schema_path, "r", encoding="utf-8") as fh:
            schema = json.load(fh)
            
        try:
            jsonschema.validate(instance=policy, schema=schema)
        except jsonschema.exceptions.ValidationError as exc:
            path_str = ".".join(str(p) for p in exc.absolute_path)
            raise PolicyValidationError(f"Policy schema validation failed at {path_str}: {exc.message}") from exc

        self._transform_and_enforce_boundaries(policy)
        return policy

    # ── logic checks & transformations ────────────────────────────────────────

    def _transform_and_enforce_boundaries(self, policy: Dict[str, Any]) -> None:
        self._check_filesystem_boundaries(policy.get("filesystem", {}))
        self._check_database_logic(policy.get("database", {}))
        self._enforce_tls_invariant(policy.get("database", {}))
        # network section is validated by JSON Schema — no extra logic needed

    @staticmethod
    def _is_subpath(child: str, parent: str) -> bool:
        try:
            return os.path.commonpath(
                [os.path.abspath(child), os.path.abspath(parent)]
            ) == os.path.abspath(parent)
        except ValueError:
            return False

    def _check_filesystem_boundaries(self, fs: Dict) -> None:
        base_paths = PolicyLoader.get_operator_base_paths()
        for i, entry in enumerate(fs.get("allowed", [])):
            prefix    = f"filesystem.allowed[{i}]"
            host_path = os.path.abspath(entry.get("host_path", ""))
            entry["host_path"] = host_path
            if base_paths and not any(
                PolicyLoader._is_subpath(host_path, bp) for bp in base_paths
            ):
                raise PolicyValidationError(
                    f"{prefix}.host_path '{host_path}' is outside "
                    f"SANDBOX_OPERATOR_BASE_PATHS: {base_paths}"
                )
            if not os.path.isabs(entry.get("sandbox_path", "")):
                raise PolicyValidationError(f"{prefix}.sandbox_path must be absolute")


    # Known drivers — matches the registry in core/db_drivers/__init__.py
    _KNOWN_DRIVERS: set = {"postgres", "postgresql", "pg", "mysql", "mariadb"}

    def _check_database_logic(self, db: Dict) -> None:
        if not db.get("enabled", False):
            return
        conn_name = db.get("connection", "primary")
        conn      = PolicyLoader.load_connection_from_env(conn_name)
        driver    = conn.get("driver", "postgres").lower()

        if driver not in PolicyLoader._KNOWN_DRIVERS:
            raise PolicyValidationError(
                f"DB_{conn_name.upper()}_DRIVER={driver!r} is not supported. "
                f"Available: {', '.join(sorted(PolicyLoader._KNOWN_DRIVERS))}"
            )
        # DB_*_HOST is not validated here — it comes from .env which may not
        # be loaded yet at container startup. The DB proxy validates it at
        # runtime when an actual connection is needed.


    def _enforce_tls_invariant(self, db: Dict[str, Any]) -> None:
        """If SANDBOX_REQUIRE_UPSTREAM_TLS=1, every enabled DB connection must use
        verify-ca or verify-full.  Configured in .env — NOT in the per-task policy
        so no task caller can lower the TLS requirement."""
        if os.environ.get("SANDBOX_REQUIRE_UPSTREAM_TLS", "0").lower() not in ("1", "true", "yes"):
            return
        if not db.get("enabled", False):
            return
        conn_name = db.get("connection", "primary")
        conn = PolicyLoader.load_connection_from_env(conn_name)
        mode = (conn.get("upstream_ssl_mode") or "").strip().lower()
        if mode not in {"verify-ca", "verify-full"}:
            raise PolicyValidationError(
                f"DB_{conn_name.upper()}_SSL_MODE must be verify-ca or verify-full "
                f"when SANDBOX_REQUIRE_UPSTREAM_TLS=1 (got {mode!r})"
            )
        if not conn.get("upstream_ssl_ca_path"):
            raise PolicyValidationError(
                f"DB_{conn_name.upper()}_SSL_CA must be set "
                f"when SANDBOX_REQUIRE_UPSTREAM_TLS=1"
            )
    # ── env-backed helpers ────────────────────────────────────────────────────

    @staticmethod
    def get_operator_base_paths() -> List[str]:
        """Read the allowed host-path boundary from env (SANDBOX_OPERATOR_BASE_PATHS)."""
        raw = os.environ.get("SANDBOX_OPERATOR_BASE_PATHS",
                             "/tmp,/data,/mnt,/var/log,/opt,/srv,/etc/ssl/certs")
        return [os.path.abspath(p.strip()) for p in raw.split(",") if p.strip()]

    @staticmethod
    def load_connection_from_env(name: str) -> Dict[str, Any]:
        """Build a DB connection dict from DB_<NAME>_* environment variables.

        The policy says which named connection to use; the actual host / port /
        credentials live in env so they never appear in policy files.
        """
        prefix = f"DB_{name.upper()}_"
        conn: Dict[str, Any] = {
            "name":           name,
            "driver":         os.environ.get(f"{prefix}DRIVER",         "postgres"),
            "host":           os.environ.get(f"{prefix}HOST",           ""),
            "port": _parse_port(f"{prefix}PORT", "5432"),
            "dbname":         os.environ.get(f"{prefix}NAME",           ""),
            "user":           os.environ.get(f"{prefix}USER",           ""),
            "password_env":   os.environ.get(f"{prefix}PASS_ENV",       ""),
            "sandbox_mount":  os.environ.get(f"{prefix}SANDBOX_MOUNT",  f"/tmp/{name}"),
            "upstream_ssl_mode": os.environ.get(f"{prefix}SSL_MODE",    "require"),
        }
        for key, suffix in (
            ("upstream_ssl_ca_path",          "SSL_CA"),
            ("upstream_ssl_client_cert_path", "SSL_CERT"),
            ("upstream_ssl_client_key_path",  "SSL_KEY"),
        ):
            val = os.environ.get(f"{prefix}{suffix}")
            if val:
                conn[key] = val
        return conn



# ── standalone validation helper (usable from CLI) ────────────────────────────

def validate_policy_file(path: str) -> None:
    """Validate a policy file and print a human-readable result."""
    try:
        loader = PolicyLoader(path)
        policy = loader.load()
        fs_cnt = len(policy.get("filesystem", {}).get("allowed", []))
        db_on  = policy.get("database", {}).get("enabled", False)
        net_on = policy.get("network",  {}).get("enabled", False)
        print(f"Policy valid: fs_rules={fs_cnt}, "
              f"database={'on' if db_on else 'off'}, network={'on' if net_on else 'off'}")
    except PolicyValidationError as exc:
        print(f"FAILED: Policy invalid: {exc}")
        raise SystemExit(1)


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "config/sandbox_policy.json"
    validate_policy_file(path)
