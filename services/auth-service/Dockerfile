FROM python:3.11-slim
WORKDIR /app
COPY shared/python /shared/python
RUN pip install --no-cache-dir /shared/python
COPY services/auth-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/auth-service/app /app/app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
