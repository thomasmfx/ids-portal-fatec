import queue

import pytest
from scapy.all import IP, TCP, UDP

from detectores.detect_portscan import DetectorPortScan


def syn(src, dport, flags="S"):
    return IP(src=src, dst="172.20.0.2") / TCP(dport=dport, flags=flags)


@pytest.fixture
def detector():
    fila = queue.Queue()
    return DetectorPortScan(fila, limite=3, janela=10.0), fila


def test_ignora_pacotes_irrelevantes_e_syn_ack(detector):
    porta_scan, fila = detector
    for pacote in (
        IP(src="10.0.0.5") / UDP(dport=53),
        syn("10.0.0.5", 80, "SA"),
        syn("10.0.0.5", 443, "A"),
    ):
        porta_scan.processar(pacote, agora=0)
    assert list(fila.queue) == []


def test_repetir_uma_porta_nao_atinge_o_limite(detector):
    porta_scan, fila = detector
    for instante in range(5):
        porta_scan.processar(syn("10.0.0.5", 80), agora=instante)
    assert list(fila.queue) == []


def test_portas_distintas_geram_alerta_com_origem_e_mitre(detector):
    porta_scan, fila = detector
    for instante, porta in enumerate((22, 80, 443)):
        porta_scan.processar(syn("10.0.0.5", porta), agora=instante)
    [alerta] = list(fila.queue)
    assert alerta["tipo"] == "Port Scan"
    assert alerta["ip_origem"] == "10.0.0.5"
    assert alerta["mitre"] == "T1046"
    assert alerta["severidade"] == "media"


def test_portas_fora_da_janela_expiram(detector):
    porta_scan, fila = detector
    for instante, porta in ((0, 22), (6, 80), (12, 443)):
        porta_scan.processar(syn("10.0.0.5", porta), agora=instante)
    assert list(fila.queue) == []


def test_silencio_e_ips_independentes(detector):
    porta_scan, fila = detector
    for instante, porta in enumerate((22, 80, 443)):
        porta_scan.processar(syn("10.0.0.5", porta), agora=instante)
    for instante, porta in enumerate((8080, 8443, 3000), start=3):
        porta_scan.processar(syn("10.0.0.5", porta), agora=instante)
    for instante, porta in enumerate((22, 80, 443), start=4):
        porta_scan.processar(syn("10.0.0.6", porta), agora=instante)
    assert [alerta["ip_origem"] for alerta in list(fila.queue)] == ["10.0.0.5", "10.0.0.6"]
