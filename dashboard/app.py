"""Dashboard Web do IDS Portal Fatec."""
import os
import sqlite3
from pathlib import Path
from flask import Flask, jsonify, render_template

app = Flask(__name__)

CAMINHO_DB = os.environ.get("IDS_DB_PATH", "/data/alerts.db")
app.config["DB_PATH"] = CAMINHO_DB


def obter_conexao(caminho_db=None):
    """Conecta ao SQLite em modo somente leitura (URI) se o arquivo existir."""
    alvo = Path(caminho_db or app.config.get("DB_PATH") or CAMINHO_DB)
    if not alvo.exists():
        return None
    # Modo read-only seguro para o SQLite montado como :ro no contêiner
    try:
        uri = f"{alvo.resolve().as_uri()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.OperationalError:
        # Fallback para ambientes de teste local onde file: uri pode variar
        conn = sqlite3.connect(alvo)
        conn.row_factory = sqlite3.Row
        return conn


def carregar_dados(caminho_db=None):
    conn = obter_conexao(caminho_db)
    if conn is None:
        return {
            "conectado": False,
            "total_alertas": 0,
            "altos": 0,
            "medios": 0,
            "baixos": 0,
            "ips_unicos": 0,
            "alertas": [],
            "por_tipo": {},
        }

    try:
        cur = conn.cursor()

        # Alertas mais recentes (limite de 100 para visualização)
        cur.execute("SELECT * FROM alertas ORDER BY id DESC LIMIT 100")
        alertas = [dict(row) for row in cur.fetchall()]

        # Contagens de severidade
        cur.execute("""
            SELECT severidade, COUNT(*) as qtd 
            FROM alertas 
            GROUP BY severidade
        """)
        sev_counts = {row["severidade"]: row["qtd"] for row in cur.fetchall()}

        # Total de IPs distintos atacantes
        cur.execute("SELECT COUNT(DISTINCT ip_origem) as qtd FROM alertas")
        row_ips = cur.fetchone()
        ips_unicos = row_ips["qtd"] if row_ips else 0

        # Alertas agrupados por tipo
        cur.execute("""
            SELECT tipo, COUNT(*) as qtd 
            FROM alertas 
            GROUP BY tipo 
            ORDER BY qtd DESC
        """)
        por_tipo = {row["tipo"]: row["qtd"] for row in cur.fetchall()}

        total_alertas = sum(sev_counts.values())

        return {
            "conectado": True,
            "total_alertas": total_alertas,
            "altos": sev_counts.get("alta", 0),
            "medios": sev_counts.get("media", 0),
            "baixos": sev_counts.get("baixa", 0),
            "ips_unicos": ips_unicos,
            "alertas": alertas,
            "por_tipo": por_tipo,
        }
    except Exception as e:
        app.logger.warning("Falha ao consultar alertas no SQLite: %s", e)
        return {
            "conectado": False,
            "total_alertas": 0,
            "altos": 0,
            "medios": 0,
            "baixos": 0,
            "ips_unicos": 0,
            "alertas": [],
            "por_tipo": {},
        }
    finally:
        conn.close()


@app.route("/")
def index():
    dados = carregar_dados()
    return render_template("index.html", dados=dados)


@app.route("/api/alertas")
def api_alertas():
    """Endpoint JSON para atualização em tempo real via polling do frontend."""
    dados = carregar_dados()
    return jsonify(dados)


if __name__ == "__main__":
    porta = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=porta, debug=True)
