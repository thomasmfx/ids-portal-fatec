FROM python:3.12-slim AS base

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && mkdir -p /var/log/vitima
COPY . .

# docker build --target teste -t vitima-teste vitima/
FROM base AS teste
RUN pip install --no-cache-dir -r requirements-dev.txt
CMD ["pytest", "-v"]

# alvo padrão do docker build e do docker compose
FROM base
EXPOSE 5000
CMD ["gunicorn", "--preload", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "app:criar_app()"]
