import json
import logging
import queue
import shutil
import signal
import subprocess
import sys
import threading

import pytest

import core


@pytest.fixture
def pasta_detectores(tmp_path, monkeypatch):
    # nome diferente de "detectores" para não colidir com o pacote real já importado
    pasta = tmp_path / "detectores_teste"
    pasta.mkdir()
    monkeypatch.syspath_prepend(tmp_path)
    yield pasta
    for nome in [m for m in sys.modules if m.startswith("detectores_teste")]:
        del sys.modules[nome]


def test_carrega_so_detectores_validos(pasta_detectores, caplog):
    arquivos = {
        "detect_ok": "def detectar(fila_alertas):\n    pass\n",
        "detect_sem_funcao": "x = 1\n",
        "detect_quebrado": "import modulo_que_nao_existe\n",
        "utilitario": "def detectar(fila_alertas):\n    pass\n",
    }
    for nome, codigo in arquivos.items():
        (pasta_detectores / f"{nome}.py").write_text(codigo, encoding="utf-8")

    detectores = core.descobrir_detectores(pasta_detectores)

    assert list(detectores) == ["detect_ok"]
    assert len([r for r in caplog.records if r.levelno >= logging.ERROR]) == 2


def test_consumir_console_imprime_alertas_e_para_no_sentinela(capsys):
    fila = queue.Queue()
    fila.put({"tipo": "Teste", "ip_origem": "10.0.0.1"})
    fila.put(None)

    core.consumir_console(fila)

    linhas = [json.loads(linha) for linha in capsys.readouterr().out.splitlines()]
    assert linhas == [{"tipo": "Teste", "ip_origem": "10.0.0.1"}]


@pytest.mark.skipif(sys.platform == "win32", reason="SIGTERM gracioso só existe em POSIX; rode no contêiner")
def test_alerta_do_detector_chega_ao_console_e_sigterm_encerra(tmp_path):
    for arquivo in ("core.py", "alerta.py"):
        shutil.copy(core.PASTA / arquivo, tmp_path)
    (tmp_path / "detectores").mkdir()
    (tmp_path / "detectores" / "detect_fake.py").write_text(
        "from alerta import novo_alerta\n\n"
        "def detectar(fila_alertas):\n"
        "    fila_alertas.put(novo_alerta('Teste', '10.0.0.9', 'alerta de teste', 'T0000'))\n",
        encoding="utf-8",
    )
    proc = subprocess.Popen(
        [sys.executable, "-u", "core.py"], cwd=tmp_path, stdout=subprocess.PIPE, text=True
    )
    # evita travar a suíte se o core nunca imprimir o alerta
    guarda = threading.Timer(15, proc.kill)
    guarda.start()
    try:
        alerta = next((json.loads(l) for l in proc.stdout if l.startswith("{")), None)
        proc.send_signal(signal.SIGTERM)
        restante = proc.communicate(timeout=10)[0]
    finally:
        guarda.cancel()
        proc.kill()

    assert alerta is not None
    assert alerta["ip_origem"] == "10.0.0.9"
    assert proc.returncode == 0
    assert "encerrando" in restante
