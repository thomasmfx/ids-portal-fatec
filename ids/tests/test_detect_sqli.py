import queue

from detectores.access_log import Requisicao
from detectores.detect_sqli import DetectorSqliXss


def requisicao(caminho, ip="10.0.0.5", user_agent="Mozilla/5.0"):
    return Requisicao(ip, "-", "", "GET", caminho, 200, 0, "-", user_agent)


def test_detecta_sqli_url_encoded():
    fila = queue.Queue()
    detector = DetectorSqliXss(fila)

    detector.processar(requisicao("/busca?q=%27+OR+1%3D1--"), agora=0)

    [alerta] = list(fila.queue)
    assert alerta["tipo"] == "SQL Injection"
    assert alerta["ip_origem"] == "10.0.0.5"
    assert alerta["mitre"] == "T1190"
    assert alerta["severidade"] == "alta"


def test_detecta_sqlmap_e_xss_sem_confundir_tipos():
    fila = queue.Queue()
    detector = DetectorSqliXss(fila)

    detector.processar(requisicao("/produtos?id=1", user_agent="sqlmap/1.8"), agora=0)
    detector.processar(requisicao("/busca?q=%3Cscript%3Ealert(1)%3C/script%3E"), agora=1)

    assert [alerta["tipo"] for alerta in list(fila.queue)] == ["SQL Injection", "XSS"]


def test_ignora_buscas_sem_assinatura_de_ataque():
    fila = queue.Queue()
    detector = DetectorSqliXss(fila)

    detector.processar(requisicao("/busca?q=select+livros"), agora=0)
    detector.processar(requisicao("/docs?tema=javascript"), agora=1)

    assert list(fila.queue) == []


def test_silencio_por_ip_e_tipo_expira():
    fila = queue.Queue()
    detector = DetectorSqliXss(fila, janela_silencio=10)
    ataque = requisicao("/busca?q=%27+OR+1%3D1--")

    detector.processar(ataque, agora=0)
    detector.processar(ataque, agora=1)
    detector.processar(ataque, agora=10)

    assert len(list(fila.queue)) == 2
