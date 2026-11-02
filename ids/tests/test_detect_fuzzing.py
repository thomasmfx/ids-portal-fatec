import queue

from detectores.access_log import Requisicao
from detectores.detect_fuzzing import DetectorFuzzing


def requisicao(caminho="/inexistente", status=404, ip="172.20.0.3", user_agent="gobuster/3.6"):
    return Requisicao(ip, "-", "", "GET", caminho, status, 207, "-", user_agent)


def test_detecta_excesso_de_404_do_mesmo_ip():
    fila = queue.Queue()
    detector = DetectorFuzzing(fila, limite=4, janela=30)

    for i, pasta in enumerate(("/admin", "/backup", "/.env", "/wp-admin")):
        detector.processar(requisicao(pasta), agora=float(i))

    [alerta] = list(fila.queue)
    assert alerta["tipo"] == "Fuzzing de Diretórios"
    assert alerta["ip_origem"] == "172.20.0.3"
    assert alerta["mitre"] == "T1595"
    assert alerta["severidade"] == "media"
    assert "/wp-admin" in alerta["descricao"]


def test_ignora_respostas_que_nao_sao_404():
    fila = queue.Queue()
    detector = DetectorFuzzing(fila, limite=3, janela=30)

    for i, status in enumerate((200, 302, 401, 403, 500, 200)):
        detector.processar(requisicao("/login", status=status), agora=float(i))
    detector.processar(requisicao("/nao-existe", status=404), agora=10.0)
    detector.processar(requisicao("/outro", status=404), agora=11.0)

    assert list(fila.queue) == []


def test_nao_soma_erros_404_de_ips_diferentes():
    fila = queue.Queue()
    detector = DetectorFuzzing(fila, limite=3, janela=30)

    for i, ip in enumerate(("10.0.0.1", "10.0.0.2", "10.0.0.1", "10.0.0.2")):
        detector.processar(requisicao(f"/rota-{i}", ip=ip), agora=float(i))

    assert list(fila.queue) == []


def test_silencia_durante_janela_e_volta_a_alertar_depois():
    fila = queue.Queue()
    detector = DetectorFuzzing(fila, limite=3, janela=10)

    # Primeiro burst atinge o limite em t=2 e silencia até t=12
    for t in (0.0, 1.0, 2.0, 3.0, 4.0, 5.0):
        detector.processar(requisicao(f"/dir-{int(t)}"), agora=t)

    assert len(list(fila.queue)) == 1

    # Após a janela de silêncio expirar, um novo burst gera segundo alerta
    for t in (13.0, 14.0, 15.0):
        detector.processar(requisicao(f"/novo-{int(t)}"), agora=t)

    assert len(list(fila.queue)) == 2


def test_expira_404_antigos_fora_da_janela():
    fila = queue.Queue()
    detector = DetectorFuzzing(fila, limite=3, janela=10)

    detector.processar(requisicao("/antigo-1"), agora=0.0)
    detector.processar(requisicao("/antigo-2"), agora=2.0)
    detector.processar(requisicao("/recente"), agora=15.0)

    assert list(fila.queue) == []
