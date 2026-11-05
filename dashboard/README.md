# Dashboard do IDS Portal Fatec

Interface web em Flask para acompanhamento em tempo real dos alertas gerados pelo IDS.

## Como funciona
- Lê o banco SQLite `alerts.db` montado em `/data/alerts.db` em modo somente leitura (`:ro`).
- Exibe métricas de ataques em tempo real: total de alertas, severidade alta/média/baixa e IPs únicos atacantes.
- Atualização dinâmica em tempo real (polling automático a cada 3 segundos via endpoint `/api/alertas`).
- Mapeamento explícito das táticas e técnicas do **MITRE ATT&CK**.

## Como rodar localmente (sem Docker)
```bash
pip install -r requirements.txt
python app.py
```
O painel ficará acessível em `http://localhost:8080`.

## Testes

Com Docker (mesmo padrão de `ids/` e `vitima/`):

```bash
docker build --target teste -t dashboard-teste dashboard/
docker run --rm dashboard-teste
```

Ou localmente com `pytest`:

```bash
cd dashboard
pytest -v
```

