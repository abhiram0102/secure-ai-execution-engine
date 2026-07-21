# production.Dockerfile
# This Dockerfile builds the entire system into a single container for AWS deployment!
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    python3 python3-pip \
    bubblewrap \
    libseccomp-dev \
    libcap-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the advanced sandbox files
COPY advanced-sandbox/supervisor.py .
COPY advanced-sandbox/exec_harness.c .
COPY advanced-sandbox/seccomp_allow.txt .
COPY advanced-sandbox/landlock_ruleset.json .
COPY advanced-sandbox/dispatcher.py /opt/dispatcher.py

# Copy the Host Application and AI code
COPY main_app.py .
COPY ai_code.py .
COPY run_production.sh .

# Build seccomp BPF from the allow-list
RUN if command -v scmp >/dev/null 2>&1; then \
        scmp syscall -d seccomp_allow.txt > /etc/seccomp/default.bin; \
    else \
        echo "scmp not found, seccomp filter will need to be built differently"; \
    fi

# Build exec_harness (the C program that launches bubblewrap)
RUN gcc -Wall -O2 -o /opt/exec_harness exec_harness.c -lcap -lseccomp

# Make the runner script executable
RUN chmod +x run_production.sh

# Start the Host Application
CMD ["./run_production.sh"]
