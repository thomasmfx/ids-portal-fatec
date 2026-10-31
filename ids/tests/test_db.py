import queue
import sqlite3

import pytest

from alerta import novo_alerta
from db import conectar, consumir


def ler_alertas(caminho):
    with sqlite3.connect(caminho) as conexao:
        return conexao.execute(
            "SELECT timestamp, tipo, ip_origem, descricao, mitre, severidade FROM alertas ORDER BY id"
        ).fetchall()


def test_consumir_cria_schema_e_persiste_alertas(tmp_path):
    caminho = tmp_path / "alerts.db"
    fila = queue.Queue()
    alerta = novo_alerta("Teste", "10.0.0.1", "descricao", "T0000", "media")
    fila.put(alerta)
    fila.put(None)

    consumir(fila, caminho)

    assert ler_alertas(caminho) == [tuple(alerta.values())]


def test_consumir_descarta_alerta_invalido_e_continua(tmp_path, caplog):
    caminho = tmp_path / "alerts.db"
    fila = queue.Queue()
    fila.put({"tipo": "incompleto"})
    alerta = novo_alerta("Teste", "10.0.0.2", "descricao", "T0001", "alta")
    fila.put(alerta)
    fila.put(None)

    consumir(fila, caminho)

    assert ler_alertas(caminho) == [tuple(alerta.values())]
    assert "falha ao persistir alerta" in caplog.text


def test_schema_restringe_severidade(tmp_path):
    caminho = tmp_path / "alerts.db"
    with conectar(caminho) as conexao:
        with pytest.raises(sqlite3.IntegrityError):
            conexao.execute(
                "INSERT INTO alertas VALUES (NULL, ?, ?, ?, ?, ?, ?)",
                ("2026-01-01T00:00:00+00:00", "Teste", "10.0.0.1", "descricao", "T0000", "critica"),
            )
