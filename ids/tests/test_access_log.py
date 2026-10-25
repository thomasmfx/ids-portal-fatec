import queue
import threading
import time

from detectores.access_log import interpretar, seguir


def test_interpreta_linha_do_combined_log_format():
    req = interpretar(
        '172.20.0.3 - - [25/Oct/2026:21:00:00 +0000] "GET /busca?q=%27+OR+1%3D1-- HTTP/1.1" '
        '200 512 "-" "sqlmap/1.8"'
    )
    assert req.ip == "172.20.0.3"
    assert req.metodo == "GET"
    assert req.caminho == "/busca?q=%27+OR+1%3D1--"
    assert req.caminho_decodificado == "/busca?q=' OR 1=1--"
    assert req.status == 200
    assert req.tamanho == 512
    assert req.user_agent == "sqlmap/1.8"


def test_desescapa_aspas_e_aceita_tamanho_vazio():
    req = interpretar(
        r'10.0.0.1 - admin [25/Oct/2026:21:00:00 +0000] "POST /login HTTP/1.1" 401 - "-" "Mozilla/5.0 \"Hydra\""'
    )
    assert req.usuario == "admin"
    assert req.status == 401
    assert req.tamanho == 0
    assert req.user_agent == 'Mozilla/5.0 "Hydra"'


def test_requisicao_malformada_vai_inteira_para_caminho():
    req = interpretar('10.0.0.1 - - [25/Oct/2026:21:00:00 +0000] "-" 400 0 "-" "-"')
    assert req.metodo == ""
    assert req.caminho == "-"


def test_linha_fora_do_formato_retorna_none():
    assert interpretar("isso não é uma linha de access.log") is None


def iniciar(caminho):
    linhas = queue.Queue()

    def consumir():
        for linha in seguir(caminho, intervalo=0.01):
            linhas.put(linha)

    threading.Thread(target=consumir, daemon=True).start()
    time.sleep(0.2)  # dá tempo de o seguir() abrir o arquivo e se posicionar
    return linhas


def escrever(caminho, texto, modo="a"):
    with open(caminho, modo, encoding="utf-8") as arquivo:
        arquivo.write(texto)


def test_ignora_o_que_ja_existia_e_entrega_linhas_novas(tmp_path):
    log = tmp_path / "access.log"
    escrever(log, "antiga\n")
    linhas = iniciar(log)
    escrever(log, "nova\n")
    assert linhas.get(timeout=2) == "nova"


def test_espera_o_arquivo_existir_e_le_desde_o_inicio(tmp_path):
    log = tmp_path / "access.log"
    linhas = iniciar(log)
    escrever(log, "primeira\n")
    assert linhas.get(timeout=2) == "primeira"


def test_junta_linha_escrita_em_pedacos(tmp_path):
    log = tmp_path / "access.log"
    escrever(log, "")
    linhas = iniciar(log)
    escrever(log, "meta")
    time.sleep(0.1)
    escrever(log, "de\n")
    assert linhas.get(timeout=2) == "metade"


def test_reabre_quando_o_arquivo_e_recriado(tmp_path):
    log = tmp_path / "access.log"
    escrever(log, "")
    linhas = iniciar(log)
    escrever(log, "antes\n")
    assert linhas.get(timeout=2) == "antes"
    log.unlink()
    escrever(log, "depois\n")
    assert linhas.get(timeout=2) == "depois"


def test_volta_ao_inicio_quando_o_arquivo_e_truncado(tmp_path):
    log = tmp_path / "access.log"
    escrever(log, "")
    linhas = iniciar(log)
    escrever(log, "uma linha bem longa\n")
    assert linhas.get(timeout=2) == "uma linha bem longa"
    escrever(log, "curta\n", modo="w")
    assert linhas.get(timeout=2) == "curta"
