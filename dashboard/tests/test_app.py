import sqlite3

from app import app


def criar_banco_teste(caminho):
    conn = sqlite3.connect(caminho)
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.executescript(
        """
        CREATE TABLE alertas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            tipo TEXT NOT NULL,
            ip_origem TEXT NOT NULL,
            descricao TEXT NOT NULL,
            mitre TEXT NOT NULL,
            severidade TEXT NOT NULL CHECK (severidade IN ('baixa', 'media', 'alta'))
        );
        """
    )
    conn.executemany(
        "INSERT INTO alertas (timestamp, tipo, ip_origem, descricao, mitre, severidade) VALUES (?, ?, ?, ?, ?, ?)",
        [
            (
                "2026-11-05T03:00:10+00:00",
                "Força Bruta no Login",
                "172.20.0.3",
                "5 falhas de autenticação (HTTP 401) em até 60s (alvo: /login)",
                "T1110",
                "alta",
            ),
            (
                "2026-11-05T03:00:05+00:00",
                "Fuzzing de Diretórios",
                "172.20.0.3",
                "15 respostas HTTP 404 em até 30s (último alvo: /admin)",
                "T1595",
                "media",
            ),
            (
                "2026-11-05T02:59:45+00:00",
                "XSS",
                "172.20.0.4",
                "payload de script suspeito: /busca?q=<script>alert(1)</script>",
                "T1190",
                "alta",
            ),
        ],
    )
    conn.commit()
    conn.close()


def test_dashboard_sem_banco_responde_vazio_e_desconectado(tmp_path):
    app.config.update({"TESTING": True, "DB_PATH": str(tmp_path / "inexistente.db")})
    cliente = app.test_client()

    resp_api = cliente.get("/api/alertas")
    assert resp_api.status_code == 200
    dados = resp_api.get_json()
    assert dados["conectado"] is False
    assert dados["total_alertas"] == 0
    assert dados["alertas"] == []

    resp_html = cliente.get("/")
    assert resp_html.status_code == 200
    assert "Aguardando conexão com a base de dados" in resp_html.get_data(as_text=True)


def test_dashboard_exibe_metricas_e_escapa_html_dos_alertas(tmp_path):
    caminho_db = tmp_path / "alerts.db"
    criar_banco_teste(caminho_db)
    app.config.update({"TESTING": True, "DB_PATH": str(caminho_db)})
    cliente = app.test_client()

    resp_api = cliente.get("/api/alertas")
    assert resp_api.status_code == 200
    dados = resp_api.get_json()
    assert dados["conectado"] is True
    assert dados["total_alertas"] == 3
    assert dados["altos"] == 2
    assert dados["medios"] == 1
    assert dados["baixos"] == 0
    assert dados["ips_unicos"] == 2
    assert dados["alertas"][0]["tipo"] == "XSS"
    assert dados["alertas"][2]["mitre"] == "T1110"

    html = cliente.get("/").get_data(as_text=True)
    assert "Força Bruta no Login" in html
    assert "T1110" in html
    # Garante que payloads XSS nos alertas são escapados na página
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
