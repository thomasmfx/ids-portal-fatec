"""Núcleo do IDS: sobe cada detector numa thread e leva os alertas da fila até o db.py."""
import importlib
import json
import logging
import queue
import signal
import sys
import threading
from pathlib import Path

log = logging.getLogger("core")

PASTA = Path(__file__).resolve().parent


def descobrir_detectores(pasta=PASTA / "detectores"):
    detectores = {}
    for arquivo in sorted(pasta.glob("detect_*.py")):
        nome = arquivo.stem
        try:
            modulo = importlib.import_module(f"{pasta.name}.{nome}")
        except Exception:
            log.exception("falha ao importar %s, detector ignorado", nome)
            continue
        if not callable(getattr(modulo, "detectar", None)):
            log.error("%s não tem detectar(fila_alertas), detector ignorado", nome)
            continue
        detectores[nome] = modulo.detectar
    return detectores


def consumir_console(fila_alertas):
    while (alerta := fila_alertas.get()) is not None:
        print(json.dumps(alerta, ensure_ascii=False), flush=True)


def obter_consumidor():
    try:
        import db
    except ModuleNotFoundError as e:
        if e.name != "db":
            raise
        log.warning("db.py não encontrado: alertas vão só para o console")
        return consumir_console
    return db.consumir


def main():
    logging.basicConfig(
        stream=sys.stdout,
        level=logging.INFO,
        format="%(asctime)s [%(threadName)s] %(levelname)s %(message)s",
    )
    fila_alertas = queue.Queue()
    parar = threading.Event()
    for sinal in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sinal, lambda *_: parar.set())

    consumidor = threading.Thread(target=obter_consumidor(), args=(fila_alertas,), name="db")
    consumidor.start()

    detectores = descobrir_detectores()
    if not detectores:
        log.warning("nenhum detector carregado")
    for nome, detectar in detectores.items():
        # daemon: sniff() e tail -f não retornam, então os detectores morrem junto com o processo
        threading.Thread(target=detectar, args=(fila_alertas,), name=nome, daemon=True).start()
    log.info("IDS no ar com %d detector(es): %s", len(detectores), ", ".join(detectores))

    parar.wait()
    log.info("encerrando: gravando alertas pendentes")
    fila_alertas.put(None)
    consumidor.join(timeout=5)


if __name__ == "__main__":
    main()
