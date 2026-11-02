"""Detector de Fuzzing de Diretórios por excesso de respostas HTTP 404 (MITRE ATT&CK T1595)."""
import time

from alerta import novo_alerta
from detectores.access_log import seguir_access_log
from detectores.janela import ContadorPorIp

LIMITE_404 = 15
JANELA_SEG = 30.0


class DetectorFuzzing:
    def __init__(self, fila_alertas, limite=LIMITE_404, janela=JANELA_SEG):
        self.fila_alertas = fila_alertas
        self.limite = limite
        self.janela = janela
        self._erros_por_ip = ContadorPorIp(limite=limite, janela=janela)

    def processar(self, requisicao, agora=None):
        """Conta respostas HTTP 404 por IP e enfileira alerta ao atingir o limite na janela."""
        if requisicao.status != 404:
            return

        agora = time.monotonic() if agora is None else agora
        if not self._erros_por_ip.registrar(requisicao.ip, agora=agora):
            return

        alvo = requisicao.caminho_decodificado[:120] or "/"
        self.fila_alertas.put(novo_alerta(
            "Fuzzing de Diretórios",
            requisicao.ip,
            f"{self.limite} respostas HTTP 404 em até {self.janela:g}s (último alvo: {alvo})",
            "T1595",
            "media",
        ))


def detectar(fila_alertas):
    detector = DetectorFuzzing(fila_alertas)
    for requisicao in seguir_access_log():
        detector.processar(requisicao)
