import base64

from app import criar_app


def criar_cliente(tmp_path):
    app = criar_app({
        "TESTING": True,
        "ACCESS_LOG_PATH": str(tmp_path / "access.log"),
        "DB_PATH": str(tmp_path / "portal.db"),
    })
    return app.test_client()


def test_rotas_publicas_respondem_200(tmp_path):
    cliente = criar_cliente(tmp_path)

    for rota in ("/", "/login", "/busca", "/mural", "/secretaria", "/robots.txt", "/health"):
        resp = cliente.get(rota)
        assert resp.status_code == 200, f"falha em {rota}"


def test_login_invalido_retorna_401_e_valido_retorna_200(tmp_path):
    cliente = criar_cliente(tmp_path)

    falha = cliente.post("/login", data={"usuario": "admin", "senha": "123"})
    assert falha.status_code == 401
    assert "inválidos" in falha.get_data(as_text=True)

    # Sem sessão, /painel também exige autenticação com 401
    assert cliente.get("/painel").status_code == 401

    sucesso = cliente.post("/login", data={"usuario": "admin", "senha": "fatec2026"})
    assert sucesso.status_code == 200
    assert "Bem-vindo" in sucesso.get_data(as_text=True)

    # Com sessão autenticada, /painel e /boletim abrem com 200
    assert cliente.get("/painel").status_code == 200
    assert cliente.get("/boletim").status_code == 200


def test_login_aceita_basic_auth_para_hydra(tmp_path):
    cliente = criar_cliente(tmp_path)

    errado = base64.b64encode(b"admin:errada").decode("ascii")
    r_errado = cliente.get("/login", headers={"Authorization": f"Basic {errado}"})
    assert r_errado.status_code == 401

    certo = base64.b64encode(b"aluno.ads:siga1234").decode("ascii")
    r_certo = cliente.get("/login", headers={"Authorization": f"Basic {certo}"})
    assert r_certo.status_code == 200


def test_busca_permite_consulta_normal_sqli_e_xss_refletido(tmp_path):
    cliente = criar_cliente(tmp_path)

    # Busca normal não exibe registro restrito (visivel = 0)
    normal = cliente.get("/busca?q=Segurança").get_data(as_text=True)
    assert "ISI002" in normal
    assert "ADM999" not in normal

    # Tautologia SQL Injection expõe todos os registros, inclusive o restrito
    sqli = cliente.get("/busca?q=%27+OR+1%3D1--").get_data(as_text=True)
    assert "ADM999" in sqli

    # UNION SELECT permite extrair dados de outra tabela (cenário sqlmap)
    union = cliente.get(
        "/busca?q=%27+UNION+SELECT+usuario,senha,perfil,ra+FROM+usuarios--"
    ).get_data(as_text=True)
    assert "fatec2026" in union

    # XSS refletido mantém o payload na resposta de laboratório
    xss = cliente.get("/busca?q=%3Cscript%3Ealert(1)%3C/script%3E").get_data(as_text=True)
    assert "<script>alert(1)</script>" in xss


def test_mural_publica_nova_mensagem(tmp_path):
    cliente = criar_cliente(tmp_path)

    resp = cliente.post("/mural", data={"autor": "5º ADS", "mensagem": "Teste do laboratório SI"})
    assert resp.status_code == 200
    assert "Teste do laboratório SI" in resp.get_data(as_text=True)


def test_admin_retorna_403_e_diretorios_inexistentes_retornam_404(tmp_path):
    cliente = criar_cliente(tmp_path)

    assert cliente.get("/admin").status_code == 403
    assert cliente.get("/phpmyadmin").status_code == 404
    assert cliente.get("/.env").status_code == 404
