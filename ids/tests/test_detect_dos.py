import queue

import pytest
from scapy.all import IP, TCP

from detectores.detect_dos import DetectorSynFlood


def syn(src, flags="S"):
    return IP(src=src, dst="172.20.0.2") / TCP(dport=80, flags=flags)


@pytest.fixture
def enviar():
    """Entrega pacotes ao detector com relógio simulado e devolve todos os alertas até agora."""
    fila = queue.Queue()
    detector = DetectorSynFlood(fila, limite=10, janela=5.0)

    def _enviar(pacotes, inicio=0.0, passo=0.01):
        for i, pacote in enumerate(pacotes):
            detector.processar(pacote, agora=inicio + i * passo)
        return list(fila.queue)

    return _enviar


def test_abaixo_do_limite_nao_alerta(enviar):
    assert enviar([syn("10.0.0.5")] * 9) == []


def test_flood_de_um_ip_aponta_o_atacante(enviar):
    [alerta] = enviar([syn("10.0.0.5")] * 10)
    assert alerta["ip_origem"] == "10.0.0.5"
    assert alerta["mitre"] == "T1498"
    assert alerta["severidade"] == "alta"


def test_ips_forjados_viram_multiplos(enviar):
    [alerta] = enviar([syn(f"203.0.113.{i}") for i in range(10)])
    assert alerta["ip_origem"].startswith("múltiplos")


def test_silencio_evita_alerta_por_pacote_e_libera_apos_a_janela(enviar):
    assert len(enviar([syn("10.0.0.5")] * 30)) == 1
    assert len(enviar([syn("10.0.0.5")] * 10, inicio=6.0)) == 2


def test_syns_fora_da_janela_expiram(enviar):
    assert enviar([syn("10.0.0.5")] * 20, passo=1.0) == []


@pytest.mark.parametrize("flags", ["SA", "A"])
def test_ignora_pacotes_com_ack(enviar, flags):
    assert enviar([syn("10.0.0.5", flags)] * 10) == []
