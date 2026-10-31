"""Detector conservador de SQL Injection e XSS em requisições HTTP (T1190)."""
import re
import time

from alerta import novo_alerta
from detectores.access_log import seguir_access_log
from detectores.janela import ContadorPorIp

JANELA_SILENCIO = 30.0

# As assinaturas procuram construções completas, e não palavras isoladas, para
# reduzir falsos positivos em buscas e URLs legítimas.
_ASSINATURAS_SQLI = (
    re.compile(r"\bunion\s+(?:all\s+)?select\b", re.IGNORECASE),
    re.compile(
        r"['\"]\s*(?:or|and)\s+(?:\d+|['\"][^'\"]*['\"])\s*=\s*(?:\d+|['\"][^'\"]*['\"])",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:sleep|benchmark)\s*\(", re.IGNORECASE),
)
_ASSINATURAS_XSS = (
    re.compile(r"<\s*script\b", re.IGNORECASE),
    re.compile(r"\bjavascript\s*:", re.IGNORECASE),
    re.compile(r"<[^>]+\bon\w+\s*=", re.IGNORECASE),
)
_SQLMAP = re.compile(r"\bsqlmap\b", re.IGNORECASE)


class DetectorSqliXss:
    def __init__(self, fila_alertas, janela_silencio=JANELA_SILENCIO):
        self.fila_alertas = fila_alertas
        self.janela_silencio = janela_silencio
        self._silencios = ContadorPorIp(limite=1, janela=janela_silencio)

    def processar(self, requisicao, agora=None):
        """Analisa uma Requisicao e enfileira, no máximo, um alerta por tipo/IP."""
        agora = time.monotonic() if agora is None else agora
        caminho = requisicao.caminho_decodificado
        tipos = []
        if _SQLMAP.search(requisicao.user_agent) or any(p.search(caminho) for p in _ASSINATURAS_SQLI):
            tipos.append(("SQL Injection", "payload SQL suspeito"))
        if any(p.search(caminho) for p in _ASSINATURAS_XSS):
            tipos.append(("XSS", "payload de script suspeito"))

        for tipo, resumo in tipos:
            # A chave inclui o tipo para que um XSS não esconda um SQLi do mesmo IP.
            chave_silencio = f"{requisicao.ip}|{tipo}"
            if self._silencios.registrar(chave_silencio, agora=agora):
                self.fila_alertas.put(novo_alerta(
                    tipo,
                    requisicao.ip,
                    f"{resumo}: {caminho[:300]}",
                    "T1190",
                    "alta",
                ))


def detectar(fila_alertas):
    detector = DetectorSqliXss(fila_alertas)
    for requisicao in seguir_access_log():
        detector.processar(requisicao)
