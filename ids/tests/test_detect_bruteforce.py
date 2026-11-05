import queue

from detectores.access_log import Requisicao
from detectores.detect_bruteforce import DetectorBruteforce


def requisicao(caminho="/login", status=401, ip="172.20.0.3", user_agent="hydra/9.5"):
    return Requisicao(ip, "-", "", "POST", caminho, status, 207, "-", user_agent)


def test_detecta_excesso_de_401_do_mesmo_ip():
    fila = queue.Queue()
    detector = DetectorBruteforce(fila, limite=4, janela=60)

    for i in range(4):
        detector.processar(requisicao(), agora=float(i))

    assert len(list(fila.queue)) == 1
    alerta = fila.get_nowait()
    assert alerta["tipo"] == "Força Bruta no Login"
    assert alerta["ip_origem"] == "172.20.0.3"
    assert alerta["mitre"] == "T1110"
    assert alerta["severidade"] == "alta"
    assert "4 falhas de autenticação" in alerta["descricao"]
    assert "/login" in alerta["descricao"]


def test_ignora_respostas_que_nao_sao_401():
    fila = queue.Queue()
    detector = DetectorBruteforce(fila, limite=3, janela=60)

    for i, status in enumerate((200, 302, 404, 403, 500, 200)):
        detector.processar(requisicao(status=status), agora=float(i))

    assert list(fila.queue) == []


def test_nao_soma_falhas_de_ips_diferentes():
    fila = queue.Queue()
    detector = DetectorBruteforce(fila, limite=3, janela=60)

    for i, ip in enumerate(("10.0.0.1", "10.0.0.2", "10.0.0.1", "10.0.0.2")):
        detector.processar(requisicao(ip=ip), agora=float(i))

    assert list(fila.queue) == []


def test_silencia_durante_janela_e_volta_a_alertar_depois():
    fila = queue.Queue()
    detector = DetectorBruteforce(fila, limite=3, janela=10)

    # Atinge o limite em t=2 e silencia até t=12
    for t in (0.0, 1.0, 2.0, 3.0, 4.0, 5.0):
        detector.processar(requisicao(), agora=t)

    assert len(list(fila.queue)) == 1

    # Após expirar a janela, novo burst gera o segundo alerta
    for t in (13.0, 14.0, 15.0):
        detector.processar(requisicao(), agora=t)

    assert len(list(fila.queue)) == 2


def test_expira_falhas_antigas_fora_da_janela():
    fila = queue.Queue()
    detector = DetectorBruteforce(fila, limite=3, janela=10)

    detector.processar(requisicao(), agora=0.0)
    detector.processar(requisicao(), agora=2.0)
    detector.processar(requisicao(), agora=15.0)

    assert list(fila.queue) == []
