import time

from scapy.all import IP, TCP, sniff

from alerta import novo_alerta
from detectores.janela import ContadorPorIp

LIMITE_PORTAS = 10
JANELA_SEG = 30.0

SYN, ACK = 0x02, 0x10
FILTRO_BPF = "ip and tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn"


class DetectorPortScan:
    def __init__(self, fila_alertas, limite=LIMITE_PORTAS, janela=JANELA_SEG):
        self.fila_alertas = fila_alertas
        self.limite = limite
        self.janela = janela
        self._portas_por_ip = ContadorPorIp(limite=limite, janela=janela, distintos=True)

    def processar(self, pacote, agora=None):
        if IP not in pacote or TCP not in pacote:
            return
        if int(pacote[TCP].flags) & (SYN | ACK) != SYN:
            return

        agora = time.monotonic() if agora is None else agora
        ip_origem = pacote[IP].src
        porta_destino = int(pacote[TCP].dport)
        if not self._portas_por_ip.registrar(ip_origem, valor=porta_destino, agora=agora):
            return

        self.fila_alertas.put(novo_alerta(
            "Port Scan",
            ip_origem,
            f"{self.limite} portas TCP distintas em até {self.janela:g}s",
            "T1046",
            "media",
        ))


def detectar(fila_alertas):
    sniff(filter=FILTRO_BPF, prn=DetectorPortScan(fila_alertas).processar, store=False)
