# production.Dockerfile
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# ── system packages ────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip \
    bubblewrap \
    libcap2 \
    libseccomp2 python3-seccomp \
    ca-certificates openssl \
    && rm -rf /var/lib/apt/lists/*
# ── Python packages ────────────────────────────────────────────────────────────
RUN pip3 install --no-cache-dir \
    psycopg2-binary \
    pymysql \
    sqlglot \
    jsonschema \
    requests \
    cryptography

WORKDIR /app

# ── copy project files ─────────────────────────────────────────────────────────
COPY config/                        ./config/
COPY core/                          ./core/
COPY advanced-sandbox/supervisor.py ./advanced-sandbox/
COPY advanced-sandbox/dispatcher.py ./advanced-sandbox/
COPY main_app.py                    ./
COPY run_agent_task.py              ./
COPY agent_tasks/                   ./agent_tasks/
COPY scripts/                       ./scripts/
COPY run_production.sh              ./

# dispatcher.py at /opt so the sandbox always finds it at a known path
COPY advanced-sandbox/dispatcher.py /opt/dispatcher.py

RUN chmod +x run_production.sh \
 && mkdir -p /data/reports /data/uploads /data/models /data/datasets \
             /var/log/sandbox /srv/exports /etc/bubble-wrap \
 && ln -s /app /workspace

CMD ["./run_production.sh"]
