#!/usr/bin/env bash
# run_production.sh - Entry point for the Single-Container AWS Deployment

echo "Starting Production Environment..."

# Load seccomp blob if available
SECCOMP_BLOB=""
if [ -f "/etc/seccomp/default.bin" ]; then
    SECCOMP_BLOB=$(cat "/etc/seccomp/default.bin")
    echo "Loaded seccomp filter."
fi

# Load Landlock ruleset
LANDLOCK_BLOB=""
if [ -f "/app/landlock_ruleset.json" ]; then
    LANDLOCK_BLOB=$(cat "/app/landlock_ruleset.json")
    echo "Loaded Landlock ruleset."
fi

export SECCOMP_BLOB
export LANDLOCK_BLOB

# Instead of starting an HTTP server, we just run the main application!
echo "Running main_app.py directly..."
echo "======================================"
python3 /app/main_app.py
echo "======================================"

# Finished
echo "Application finished."
