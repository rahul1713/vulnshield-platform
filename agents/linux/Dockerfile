FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="VulnShield Linux Agent"
LABEL org.opencontainers.image.description="Endpoint inventory agent for VulnShield Platform"

RUN apt-get update && apt-get install -y --no-install-recommends \
    procps \
    iproute2 \
    systemd \
    cron \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/vulnshield-agent

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY config.py agent.py ./
COPY collectors/ ./collectors/

RUN useradd -r -s /bin/false vulnshield && \
    mkdir -p /etc/vulnshield/certs && \
    chown -R vulnshield:vulnshield /opt/vulnshield-agent /etc/vulnshield

USER vulnshield

ENV VULNSHIELD_API_URL=https://api-gateway:8080/api/v1
ENV VULNSHIELD_HEARTBEAT_INTERVAL=300
ENV VULNSHIELD_INVENTORY_INTERVAL=3600

HEALTHCHECK --interval=60s --timeout=5s --retries=3 \
    CMD python -c "import socket; socket.gethostname()" || exit 1

ENTRYPOINT ["python", "agent.py"]
