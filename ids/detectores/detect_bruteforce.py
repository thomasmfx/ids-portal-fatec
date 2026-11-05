"""Detector de Força Bruta por excesso de falhas de autenticação HTTP 401 (MITRE ATT&CK T1110)."""
import time

from alerta import novo_alerta
from detectores.access_log import seguir_access_log
from detectores.janela import ContadorPorIp

# Parâmetros padrão alinhados à proposta:
# 5 tentativas com status 401 vindas do mesmo IP em até 60 segundos geram alerta.
LIMITE_401 = 5
JANELA_SEG = 60.0


class DetectorBruteforce:
    def __init__(self, fila_alertas, limite=LIMITE_401, janela=JANELA_SEG):
        self.fila_alertas = fila_alertas
        self.limite = limite
        self.janela = janela
        self._falhas_por_ip = ContadorPorIp(limite=limite, janela=janela)

    def processar(self, requisicao, agora=None):
        """Conta respostas HTTP 401 por IP e enfileira alerta ao atingir o limite na janela."""
        if requisicao.status != 401:
            return

        agora = time.monotonic() if agora is None else agora
        if not self._falhas_por_ip.registrar(requisicao.ip, agora=agora):
            return

        alvo = requisicao.caminho_decodificado[:120] or "/login"
        self.fila_alertas.put(novo_alerta(
            "Força Bruta no Login",
            requisicao.ip,
            f"{self.limite} falhas de autenticação (HTTP 401) em até {self.janela:g}s (alvo: {alvo})",
            "T1110",
            "alta",
        ))


def detectar(fila_alertas):
    detector = DetectorBruteforce(fila_alertas)
    for requisicao in seguir_access_log():
        detector.processar(requisicao)
