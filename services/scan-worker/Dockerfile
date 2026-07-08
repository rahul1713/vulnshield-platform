FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap curl git ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*

# Install nuclei
ARG NUCLEI_VERSION=3.3.7
RUN curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip \
    && nuclei -update-templates || true

WORKDIR /app
COPY shared/python /shared/python
RUN pip install --no-cache-dir /shared/python semgrep
COPY services/scan-worker/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/scan-worker/app /app/app

ENV SCAN_SANDBOX_MODE=true
ENV ALLOW_EXTERNAL_TARGETS=false

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8012"]
