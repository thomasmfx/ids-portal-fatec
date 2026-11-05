FROM python:3.12-slim AS base

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV IDS_DB_PATH=/data/alerts.db

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# docker build --target teste -t dashboard-teste dashboard/
FROM base AS teste
RUN pip install --no-cache-dir -r requirements-dev.txt
CMD ["pytest", "-v"]

# alvo padrão do docker build e do docker compose
FROM base
EXPOSE 8080
CMD ["gunicorn", "-b", "0.0.0.0:8080", "--workers", "2", "app:app"]

