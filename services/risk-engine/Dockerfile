FROM python:3.11-slim
WORKDIR /app
COPY shared/python /shared/python
RUN pip install /shared/python
COPY services/risk-engine/requirements.txt .
RUN pip install -r requirements.txt
COPY services/risk-engine/app /app/app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8008"]
