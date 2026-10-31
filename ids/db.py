"""Persistência dos alertas do IDS em SQLite.

O core inicia ``consumir`` em uma única thread. Por isso esta é a única
parte do IDS que escreve no banco e não há disputa de escrita entre os
detectores.
"""
import logging
import os
import sqlite3
from pathlib import Path

from alerta import SEVERIDADES

log = logging.getLogger(__name__)

CAMINHO_DB = os.environ.get("IDS_DB_PATH", "/data/alerts.db")
CAMPOS_ALERTA = ("timestamp", "tipo", "ip_origem", "descricao", "mitre", "severidade")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alertas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    tipo TEXT NOT NULL,
    ip_origem TEXT NOT NULL,
    descricao TEXT NOT NULL,
    mitre TEXT NOT NULL,
    severidade TEXT NOT NULL CHECK (severidade IN ('baixa', 'media', 'alta'))
);
CREATE INDEX IF NOT EXISTS idx_alertas_timestamp ON alertas(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alertas_tipo_severidade ON alertas(tipo, severidade);
"""

_INSERIR_ALERTA = """
INSERT INTO alertas (timestamp, tipo, ip_origem, descricao, mitre, severidade)
VALUES (?, ?, ?, ?, ?, ?)
"""


def conectar(caminho=CAMINHO_DB):
    """Abre o banco e garante o schema lido pelo dashboard."""
    Path(caminho).parent.mkdir(parents=True, exist_ok=True)
    conexao = sqlite3.connect(caminho)
    try:
        # DELETE é o journal padrão; não cria arquivos WAL/SHM que o dashboard
        # montado como somente leitura não conseguiria gerenciar.
        conexao.execute("PRAGMA journal_mode=DELETE")
        conexao.executescript(_SCHEMA)
        conexao.commit()
    except Exception:
        conexao.close()
        raise
    return conexao


def _valores_do_alerta(alerta):
    if not isinstance(alerta, dict):
        raise ValueError("alerta deve ser um dicionário")
    faltando = [campo for campo in CAMPOS_ALERTA if campo not in alerta]
    if faltando:
        raise ValueError(f"alerta sem campo(s) obrigatório(s): {', '.join(faltando)}")
    if alerta["severidade"] not in SEVERIDADES:
        raise ValueError(f"severidade inválida: {alerta['severidade']!r}")
    valores = tuple(alerta[campo] for campo in CAMPOS_ALERTA)
    if not all(isinstance(valor, str) and valor for valor in valores):
        raise ValueError("todos os campos do alerta devem ser textos não vazios")
    return valores


def consumir(fila_alertas, caminho=CAMINHO_DB):
    """Consome alertas até ``None`` e os persiste em SQLite.

    Um alerta inválido ou uma falha pontual de gravação é registrada no log e
    não encerra a thread consumidora nem os detectores.
    """
    try:
        conexao = conectar(caminho)
    except (OSError, sqlite3.Error):
        log.exception("não foi possível abrir o banco de alertas: %s", caminho)
        while fila_alertas.get() is not None:
            log.error("alerta descartado: banco indisponível")
        return

    try:
        while (alerta := fila_alertas.get()) is not None:
            try:
                conexao.execute(_INSERIR_ALERTA, _valores_do_alerta(alerta))
                conexao.commit()
            except (ValueError, sqlite3.Error):
                conexao.rollback()
                log.exception("falha ao persistir alerta; alerta descartado")
    finally:
        conexao.close()
