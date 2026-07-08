FROM python:3.11-slim
WORKDIR /app
ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY shared/python /shared/python
RUN pip install /shared/python
COPY services/ai-code-review/requirements.txt .
RUN pip install -r requirements.txt && pip install --no-cache-dir semgrep
COPY services/ai-code-review/app /app/app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8005"]
