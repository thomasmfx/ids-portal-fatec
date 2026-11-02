"""Gravação do access.log da vítima em Combined Log Format (padrão Apache/Nginx).

Segue o contrato esperado por `ids/detectores/access_log.py`:
- preserva caminho e query string brutos (ainda URL-encoded);
- escapa `\\`, `"` e quebras de linha nos campos entre aspas;
- escreve cada linha completa terminada em `\\n` com flush imediato.
"""
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit

CAMINHO_PADRAO = "/var/log/vitima/access.log"

_MESES = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_TRAVA_ESCRITA = threading.Lock()

log = logging.getLogger(__name__)


def escapar_campo(texto):
    """Escapa barras, aspas e quebras de linha para campos entre aspas do Combined Log Format."""
    return (
        str(texto)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )


def sanitizar_token(valor):
    """Garante um token sem espaços (ex.: IP ou usuário) ou `-` quando ausente."""
    if valor is None:
        return "-"
    texto = str(valor).strip()
    if not texto:
        return "-"
    return quote(texto[:64], safe=".:@_+-")


def formatar_instante(instante=None):
    """Formata data/hora UTC como `25/Oct/2026:21:00:00 +0000`, sem depender do locale."""
    dt = datetime.now(timezone.utc) if instante is None else instante.astimezone(timezone.utc)
    mes = _MESES[dt.month - 1]
    return f"{dt.day:02d}/{mes}/{dt.year:04d}:{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d} +0000"


def obter_alvo_bruto(req):
    """Extrai caminho + query string ainda URL-encoded, exatamente como chegaram na requisição."""
    raw_uri = req.environ.get("RAW_URI") or req.environ.get("REQUEST_URI")
    if raw_uri:
        if raw_uri.startswith(("http://", "https://")):
            partes = urlsplit(raw_uri)
            caminho = partes.path or "/"
            return f"{caminho}?{partes.query}" if partes.query else caminho
        return raw_uri

    # Fallback para clientes WSGI de teste (FlaskClient), onde QUERY_STRING continua bruta
    caminho = quote(req.path or "/", safe="/:@!$&'()*+,;=-._~")
    query_bruta = req.query_string.decode("latin-1")
    return f"{caminho}?{query_bruta}" if query_bruta else caminho


def formatar_linha(
    ip,
    metodo,
    alvo_bruto,
    protocolo,
    status,
    tamanho,
    referer="-",
    user_agent="-",
    usuario="-",
    instante=None,
):
    """Monta uma linha em Combined Log Format compatível com o parser do IDS."""
    ip_tok = sanitizar_token(ip)
    usuario_tok = sanitizar_token(usuario)
    data_str = formatar_instante(instante)
    linha_req = escapar_campo(f"{metodo} {alvo_bruto} {protocolo}")
    tamanho_str = str(int(tamanho)) if tamanho is not None else "-"
    referer_str = escapar_campo(referer or "-")
    ua_str = escapar_campo(user_agent or "-")
    return (
        f'{ip_tok} - {usuario_tok} [{data_str}] "{linha_req}" '
        f'{int(status):03d} {tamanho_str} "{referer_str}" "{ua_str}"'
    )


def registrar_requisicao(caminho_log, req, resp, usuario="-", instante=None):
    """Formata e grava imediatamente uma requisição HTTP no arquivo `access.log`."""
    linha = formatar_linha(
        ip=req.remote_addr or "-",
        metodo=req.method,
        alvo_bruto=obter_alvo_bruto(req),
        protocolo=req.environ.get("SERVER_PROTOCOL", "HTTP/1.1"),
        status=resp.status_code,
        tamanho=resp.calculate_content_length(),
        referer=req.headers.get("Referer") or "-",
        user_agent=req.headers.get("User-Agent") or "-",
        usuario=usuario,
        instante=instante,
    )
    gravar_linha(caminho_log, linha)
    return linha


def gravar_linha(caminho_log, linha):
    """Escreve uma linha completa em UTF-8 com flush imediato para leitura via `tail -f`."""
    dados = (linha + "\n").encode("utf-8", errors="replace")
    try:
        Path(caminho_log).parent.mkdir(parents=True, exist_ok=True)
        with _TRAVA_ESCRITA:
            with open(caminho_log, "ab") as arquivo:
                arquivo.write(dados)
                arquivo.flush()
    except OSError:
        log.exception("falha ao gravar access.log em %s", caminho_log)
