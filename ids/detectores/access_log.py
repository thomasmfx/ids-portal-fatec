"""Leitura do access.log da vítima, em Combined Log Format (o mesmo do Apache e do Nginx)."""
import logging
import os
import re
import time
from dataclasses import dataclass
from urllib.parse import unquote_plus

CAMINHO = "/var/log/vitima/access.log"

log = logging.getLogger(__name__)

_ASPAS = r'"((?:[^"\\]|\\.)*)"'
# 172.20.0.3 - - [25/Oct/2026:21:00:00 +0000] "GET /admin?id=1 HTTP/1.1" 404 207 "-" "gobuster/3.6"
_LINHA = re.compile(rf"(\S+) \S+ (\S+) \[([^\]]+)\] {_ASPAS} (\d{{3}}) (\S+) {_ASPAS} {_ASPAS}")
_REQUISICAO = re.compile(r"(\S+) (.*) (HTTP/[\d.]+)")


@dataclass(frozen=True)
class Requisicao:
    ip: str
    usuario: str
    instante: str
    metodo: str
    caminho: str  # como veio na requisição, ainda URL-encoded
    status: int
    tamanho: int
    referer: str
    user_agent: str

    @property
    def caminho_decodificado(self):
        """Caminho com %27, + etc. convertidos: é aqui que um payload como ' OR 1=1 fica legível."""
        return unquote_plus(self.caminho)


def interpretar(linha):
    """Converte uma linha do access.log em Requisicao, ou None se ela não seguir o formato."""
    partes = _LINHA.match(linha)
    if not partes:
        return None
    ip, usuario, instante, requisicao, status, tamanho, referer, user_agent = partes.groups()
    requisicao = _desescapar(requisicao)
    linha_requisicao = _REQUISICAO.fullmatch(requisicao)
    # requisição malformada (comum em fuzzing) não tem método nem protocolo: o texto bruto vai em caminho
    metodo, caminho = linha_requisicao.group(1, 2) if linha_requisicao else ("", requisicao)
    return Requisicao(
        ip=ip,
        usuario=usuario,
        instante=instante,
        metodo=metodo,
        caminho=caminho,
        status=int(status),
        tamanho=int(tamanho) if tamanho.isdigit() else 0,
        referer=_desescapar(referer),
        user_agent=_desescapar(user_agent),
    )


def seguir_access_log(caminho=CAMINHO, intervalo=0.2):
    """Gera uma Requisicao para cada linha nova do access.log."""
    for linha in seguir(caminho, intervalo):
        requisicao = interpretar(linha)
        if requisicao is None:
            log.warning("linha fora do Combined Log Format ignorada: %.200s", linha)
            continue
        yield requisicao


def seguir(caminho, intervalo=0.2):
    """Gera cada linha nova do arquivo, como `tail -f`.

    Se o arquivo já existe, começa do fim: o que já estava lá não é reprocessado. Se ainda não
    existe, espera ser criado e lê desde o início. Se for truncado ou recriado, reabre do início.
    """
    arquivo = _abrir(caminho, intervalo, do_fim=True)
    pendente = b""
    while True:
        trecho = arquivo.readline()
        if trecho:
            pendente += trecho
            # a vítima pode estar no meio da escrita: só entrega a linha quando chegar o \n
            if pendente.endswith(b"\n"):
                yield pendente.rstrip(b"\r\n").decode("utf-8", errors="replace")
                pendente = b""
            continue
        time.sleep(intervalo)
        if _foi_trocado(caminho, arquivo):
            arquivo.close()
            arquivo = _abrir(caminho, intervalo, do_fim=False)
            pendente = b""


def _desescapar(texto):
    return re.sub(r"\\(.)", r"\1", texto)


def _abrir(caminho, intervalo, do_fim):
    while True:
        try:
            arquivo = open(caminho, "rb")
        except FileNotFoundError:
            do_fim = False
            time.sleep(intervalo)
            continue
        if do_fim:
            arquivo.seek(0, os.SEEK_END)
        return arquivo


def _foi_trocado(caminho, arquivo):
    try:
        atual = os.stat(caminho)
    except FileNotFoundError:
        return True
    return atual.st_ino != os.fstat(arquivo.fileno()).st_ino or atual.st_size < arquivo.tell()
