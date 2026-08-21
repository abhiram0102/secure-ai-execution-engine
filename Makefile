# Bubble-Wrap Sandbox — build & CI targets
#
# Usage:
#   make            # default: unit tests + policy validation
#   make evasion    # run the sandbox evasion suite (needs bwrap + databases)
#   make gate       # enforce the CSV gate (fails on any not-Pass row)
#   make ci         # full pipeline: unit + policy + evasion + gate

PY ?= python3

.PHONY: default all unit policy evasion gate ci clean help

default: unit policy  ## Run unit tests and policy validation (default)

all: ci  ## Full CI pipeline

# ─── Unit tests (Windows-safe, no docker/kernel needed) ──────────────────────
unit:  ## Run unit tests (no docker/kernel needed)
	$(PY) -m pytest tests/test_policy_loader_security.py \
	                tests/test_db_proxy_tls.py \
	                tests/test_run_evasion_extract.py \
	                tests/test_verify_csv_gate.py -v

# ─── Policy schema validation (fast fail on any bad JSON) ────────────────────
policy:  ## Validate all policy JSON files against the schema
	@$(PY) -c "import json,jsonschema,glob; \
s=json.load(open('config/sandbox_policy.schema.json')); \
jsonschema.Draft7Validator.check_schema(s); \
paths=['config/sandbox_policy.json']+sorted(glob.glob('agent_tasks/task_*_policy.json')); \
[jsonschema.validate(json.load(open(p)), s) for p in paths]; \
print(f'SCHEMA OK ({len(paths)} policies validated)')"

# ─── Run the sandbox evasion attack suite ───────────────────────────────────
evasion:  ## Run evasion test suite (needs bwrap + running databases)
	$(PY) tests/run_evasion_tests.py --run-all

# ─── Enforce the CI gate on the CSV ─────────────────────────────────────────
gate:  ## Fail if any evasion test is not Pass in the CSV
	$(PY) tests/verify_csv_all_pass.py

# ─── Full CI pipeline ───────────────────────────────────────────────────────
ci: unit policy evasion gate  ## Full pipeline: unit + policy + evasion + gate
	@echo "CI green — all controls verified."

clean:  ## Remove __pycache__ and .pytest_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type d -name .pytest_cache -prune -exec rm -rf {} +

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) | \
	 awk 'BEGIN{FS=":.*?##"};{printf "  \033[36m%-10s\033[0m %s\n",$$1,$$2}'
