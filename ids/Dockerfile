FROM python:3.12-slim AS base

# O Scapy chama o tcpdump para compilar os filtros BPF passados ao sniff(filter=...)
RUN apt-get update \
    && apt-get install -y --no-install-recommends tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# docker build --target teste: mesma imagem + pytest, sem levar dependência de dev para produção
FROM base AS teste
RUN pip install --no-cache-dir -r requirements-dev.txt
CMD ["pytest", "-v"]

# último estágio = alvo padrão do docker build e do compose
FROM base
CMD ["python", "-u", "core.py"]
