"""Detector de DoS por SYN Flood (MITRE ATT&CK T1498 - Network Denial of Service)."""
import time
from collections import Counter, deque

from scapy.all import IP, TCP, sniff

from alerta import novo_alerta

LIMITE_SYN = 200
JANELA_SEG = 5.0

SYN, ACK = 0x02, 0x10
# SYN ligado e ACK desligado: só aberturas de conexão, não as respostas SYN-ACK da vítima
FILTRO_BPF = "tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn"


class DetectorSynFlood:
    def __init__(self, fila_alertas, limite=LIMITE_SYN, janela=JANELA_SEG):
        self.fila_alertas = fila_alertas
        self.limite = limite
        self.janela = janela
        self._syns = deque()  # (instante, ip de origem)
        self._silencio_ate = float("-inf")

    def processar(self, pacote, agora=None):
        if IP not in pacote or TCP not in pacote:
            return
        if int(pacote[TCP].flags) & (SYN | ACK) != SYN:
            return
        agora = time.monotonic() if agora is None else agora
        self._syns.append((agora, pacote[IP].src))
        while self._syns[0][0] <= agora - self.janela:
            self._syns.popleft()

        if len(self._syns) < self.limite or agora < self._silencio_ate:
            return
        ip, qtd = Counter(ip for _, ip in self._syns).most_common(1)[0]
        # com hping3 --rand-source cada SYN vem de um IP forjado, então nenhum domina a janela
        origem = ip if qtd * 2 >= len(self._syns) else "múltiplos (possível IP spoofing)"
        self.fila_alertas.put(novo_alerta(
            "DoS (SYN Flood)",
            origem,
            f"{len(self._syns)} pacotes SYN em {self.janela:g}s (limite {self.limite})",
            "T1498",
            "alta",
        ))
        # um alerta por janela; sem isso o flood geraria um alerta por pacote
        self._silencio_ate = agora + self.janela


def detectar(fila_alertas):
    sniff(filter=FILTRO_BPF, prn=DetectorSynFlood(fila_alertas).processar, store=False)
