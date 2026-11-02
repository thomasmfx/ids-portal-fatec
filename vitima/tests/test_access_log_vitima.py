import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from access_log import formatar_instante, formatar_linha
from app import criar_app

_ASPAS = r'"((?:[^"\\]|\\.)*)"'
_REGEX_CLF = re.compile(
    rf"(\S+) \S+ (\S+) \[([^\]]+)\] {_ASPAS} (\d{{3}}) (\S+) {_ASPAS} {_ASPAS}"
)


def criar_cliente(tmp_path):
    log_path = tmp_path / "access.log"
    db_path = tmp_path / "portal.db"
    app = criar_app({"TESTING": True, "ACCESS_LOG_PATH": str(log_path), "DB_PATH": str(db_path)})
    return app.test_client(), log_path


def test_formatar_instante_em_ingles_independente_do_locale():
    dt = datetime(2026, 10, 25, 21, 0, 0, tzinfo=timezone.utc)
    assert formatar_instante(dt) == "25/Oct/2026:21:00:00 +0000"


def test_formatar_linha_escapa_aspas_barras_e_quebras_de_linha():
    dt = datetime(2026, 10, 25, 21, 0, 0, tzinfo=timezone.utc)
    linha = formatar_linha(
        ip="10.0.0.1",
        metodo="POST",
        alvo_bruto="/login",
        protocolo="HTTP/1.1",
        status=401,
        tamanho=320,
        referer="-",
        user_agent='Mozilla/5.0 "Hydra"\nFalso',
        usuario="admin",
        instante=dt,
    )
    assert "\n" not in linha
    m = _REGEX_CLF.fullmatch(linha)
    assert m is not None
    assert m.group(1) == "10.0.0.1"
    assert m.group(2) == "admin"
    assert m.group(5) == "401"
    assert r'Mozilla/5.0 \"Hydra\"\nFalso' == m.group(8)


def test_preserva_query_string_url_encoded_no_access_log(tmp_path):
    cliente, log_path = criar_cliente(tmp_path)

    cliente.get(
        "/busca?q=%27+OR+1%3D1--",
        headers={"User-Agent": 'sqlmap/1.8 "teste"'},
        environ_base={"REMOTE_ADDR": "172.20.0.3"},
    )

    [linha] = log_path.read_text(encoding="utf-8").splitlines()
    m = _REGEX_CLF.fullmatch(linha)
    assert m is not None
    assert m.group(1) == "172.20.0.3"
    assert m.group(4) == "GET /busca?q=%27+OR+1%3D1-- HTTP/1.1"
    assert m.group(5) == "200"
    assert m.group(8) == r'sqlmap/1.8 \"teste\"'


def test_registra_404_e_401_no_access_log(tmp_path):
    cliente, log_path = criar_cliente(tmp_path)

    cliente.get("/wp-admin", headers={"User-Agent": "gobuster/3.6"})
    cliente.post("/login", data={"usuario": "admin", "senha": "errada"})

    linhas = log_path.read_text(encoding="utf-8").splitlines()
    assert len(linhas) == 2

    m_404 = _REGEX_CLF.fullmatch(linhas[0])
    m_401 = _REGEX_CLF.fullmatch(linhas[1])
    assert m_404 and m_404.group(5) == "404" and "/wp-admin" in m_404.group(4)
    assert m_401 and m_401.group(5) == "401" and m_401.group(2) == "admin"


def test_contrato_ponta_a_ponta_com_parser_do_ids(tmp_path):
    pasta_ids = Path(__file__).resolve().parents[2] / "ids"
    if not (pasta_ids / "detectores" / "access_log.py").exists():
        return  # execução isolada dentro do contêiner da vítima

    sys.path.insert(0, str(pasta_ids))
    try:
        import queue

        import db
        from detectores.access_log import interpretar
        from detectores.detect_fuzzing import DetectorFuzzing
        from detectores.detect_sqli import DetectorSqliXss

        cliente, log_path = criar_cliente(tmp_path)
        cliente.get(
            "/busca?q=%27+OR+1%3D1--",
            headers={"User-Agent": 'Mozilla/5.0 "Hydra"', "Referer": "http://fatec.local/"},
            environ_base={"REMOTE_ADDR": "172.20.0.9"},
        )
        for i in range(4):
            cliente.get(f"/diretorio-secreto-{i}", environ_base={"REMOTE_ADDR": "172.20.0.9"})

        linhas = log_path.read_text(encoding="utf-8").splitlines()
        requisicoes = [interpretar(l) for l in linhas]
        assert all(r is not None for r in requisicoes)

        req1 = requisicoes[0]
        assert req1.ip == "172.20.0.9"
        assert req1.metodo == "GET"
        assert req1.caminho == "/busca?q=%27+OR+1%3D1--"
        assert req1.caminho_decodificado == "/busca?q=' OR 1=1--"
        assert req1.status == 200
        assert req1.user_agent == 'Mozilla/5.0 "Hydra"'

        fila = queue.Queue()
        det_sqli = DetectorSqliXss(fila)
        det_fuzz = DetectorFuzzing(fila, limite=4, janela=30)
        for idx, req in enumerate(requisicoes):
            det_sqli.processar(req, agora=float(idx))
            det_fuzz.processar(req, agora=float(idx))
        fila.put(None)

        alerts_db = tmp_path / "alerts.db"
        db.consumir(fila, caminho=str(alerts_db))
        with db.conectar(str(alerts_db)) as con:
            gravados = con.execute("SELECT tipo, mitre FROM alertas ORDER BY id").fetchall()
        assert gravados == [("SQL Injection", "T1190"), ("Fuzzing de Diretórios", "T1595")]
    finally:
        sys.path.remove(str(pasta_ids))
