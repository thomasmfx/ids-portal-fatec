"""Aplicação Flask vulnerável ("Portal Fatec") monitorada pelo IDS.

Expõe as rotas atacadas no laboratório (login, busca, mural, diretórios) e
registra todas as requisições em `/var/log/vitima/access.log` no formato
Combined Log Format consumido pelos detectores do IDS.
"""
import os
import sqlite3
from datetime import datetime, timezone

from flask import (
    Flask,
    Response,
    abort,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from access_log import CAMINHO_PADRAO, registrar_requisicao
from banco import (
    CAMINHO_DB_PADRAO,
    autenticar_usuario,
    buscar_disciplinas_vulneravel,
    inicializar_banco,
    listar_mural,
    listar_notas,
    obter_usuario,
    publicar_mural,
)


def _extrair_credenciais(req):
    """Aceita credenciais via formulário HTML, JSON ou HTTP Basic Auth."""
    if req.form:
        usuario = req.form.get("usuario") or req.form.get("username") or ""
        senha = req.form.get("senha") or req.form.get("password") or ""
        return usuario.strip(), senha

    dados = req.get_json(silent=True)
    if isinstance(dados, dict):
        usuario = str(dados.get("usuario") or dados.get("username") or "").strip()
        senha = str(dados.get("senha") or dados.get("password") or "")
        return usuario, senha

    if req.authorization:
        return (req.authorization.username or "").strip(), req.authorization.password or ""

    return "", ""


def criar_app(config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("VITIMA_SECRET_KEY", "fatec-mogi-lab-si-2026"),
        ACCESS_LOG_PATH=os.environ.get("VITIMA_ACCESS_LOG", CAMINHO_PADRAO),
        DB_PATH=os.environ.get("VITIMA_DB_PATH", CAMINHO_DB_PADRAO),
    )
    if config:
        app.config.update(config)

    inicializar_banco(app.config["DB_PATH"])

    @app.context_processor
    def injetar_usuario():
        return {"usuario_sessao": session.get("usuario")}

    @app.after_request
    def logar_requisicao(resposta):
        usuario = (
            getattr(g, "usuario_log", None)
            or session.get("usuario")
            or (request.authorization.username if request.authorization else None)
            or "-"
        )
        registrar_requisicao(app.config["ACCESS_LOG_PATH"], request, resposta, usuario=usuario)
        return resposta

    @app.route("/")
    def index():
        avisos = listar_mural(app.config["DB_PATH"])[:5]
        return render_template("index.html", avisos=avisos)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        # Suporta Hydra tanto via POST form quanto via GET com Basic Auth
        if request.method == "GET" and not request.authorization:
            return render_template("login.html", erro=None, usuario_informado="")

        usuario, senha = _extrair_credenciais(request)
        g.usuario_log = usuario or "-"
        dados = autenticar_usuario(app.config["DB_PATH"], usuario, senha)

        if dados is None:
            resposta = Response(
                render_template(
                    "login.html",
                    erro="Usuário ou senha inválidos.",
                    usuario_informado=usuario,
                ),
                status=401,
            )
            if request.authorization:
                resposta.headers["WWW-Authenticate"] = 'Basic realm="Portal Fatec"'
            return resposta

        session["usuario"] = dados["usuario"]
        notas = listar_notas(app.config["DB_PATH"], dados["usuario"])
        return render_template("painel.html", dados_usuario=dados, notas=notas), 200

    @app.route("/logout")
    def logout():
        g.usuario_log = session.get("usuario") or "-"
        session.clear()
        return redirect(url_for("login"))

    @app.route("/painel")
    @app.route("/boletim")
    def painel():
        usuario = session.get("usuario")
        dados = obter_usuario(app.config["DB_PATH"], usuario) if usuario else None
        if dados is None:
            return (
                render_template(
                    "login.html",
                    erro="Autenticação necessária para consultar o boletim.",
                    usuario_informado="",
                ),
                401,
            )
        notas = listar_notas(app.config["DB_PATH"], usuario)
        return render_template("painel.html", dados_usuario=dados, notas=notas)

    @app.route("/busca")
    def busca():
        termo = request.args.get("q", "")
        erro_sql = None
        try:
            disciplinas = buscar_disciplinas_vulneravel(app.config["DB_PATH"], termo)
        except sqlite3.Error as erro:
            disciplinas = []
            erro_sql = str(erro)
        return render_template(
            "busca.html",
            termo=termo,
            disciplinas=disciplinas,
            erro_sql=erro_sql,
        )

    @app.route("/mural", methods=["GET", "POST"])
    def mural():
        if request.method == "POST":
            autor = (request.form.get("autor") or "").strip()
            mensagem = (request.form.get("mensagem") or "").strip()
            if autor and mensagem:
                agora = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M")
                publicar_mural(app.config["DB_PATH"], autor, mensagem, agora)
        mensagens = listar_mural(app.config["DB_PATH"])
        return render_template("mural.html", mensagens=mensagens)

    @app.route("/secretaria")
    def secretaria():
        return render_template("secretaria.html")

    @app.route("/admin")
    def admin():
        abort(403)

    @app.route("/robots.txt")
    def robots():
        conteudo = "User-agent: *\nDisallow: /admin\nDisallow: /secretaria\nDisallow: /backup\n"
        return Response(conteudo, mimetype="text/plain")

    @app.route("/health")
    def health():
        return {"status": "ok"}

    @app.route("/favicon.ico")
    def favicon():
        return Response(status=204)

    @app.errorhandler(403)
    def erro_403(_erro):
        return (
            render_template(
                "erro.html",
                codigo=403,
                titulo="Acesso Restrito",
                detalhe="Este diretório é restrito à rede interna da administração.",
            ),
            403,
        )

    @app.errorhandler(404)
    def erro_404(_erro):
        return (
            render_template(
                "erro.html",
                codigo=404,
                titulo="Página Não Encontrada",
                detalhe="O endereço solicitado não foi localizado no Portal Acadêmico.",
            ),
            404,
        )

    @app.errorhandler(405)
    def erro_405(_erro):
        return (
            render_template(
                "erro.html",
                codigo=405,
                titulo="Método Não Permitido",
                detalhe="O método HTTP utilizado não é aceito nesta rota.",
            ),
            405,
        )

    @app.errorhandler(500)
    def erro_500(_erro):
        return (
            render_template(
                "erro.html",
                codigo=500,
                titulo="Erro Interno do Servidor",
                detalhe="Ocorreu uma falha inesperada ao processar a requisição.",
            ),
            500,
        )

    return app


if __name__ == "__main__":
    porta = int(os.environ.get("PORT", "5000"))
    criar_app().run(host="0.0.0.0", port=porta)
