"""Banco SQLite local de dados fictícios do Portal Fatec Mogi das Cruzes.

Usado apenas para alimentar as páginas da aplicação vítima e permitir
demonstrações reais de login, força bruta (Hydra) e SQL Injection (sqlmap).
"""
import sqlite3
from pathlib import Path

CAMINHO_DB_PADRAO = "/tmp/portal_fatec.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario TEXT UNIQUE NOT NULL,
    senha TEXT NOT NULL,
    nome TEXT NOT NULL,
    perfil TEXT NOT NULL,
    ra TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS disciplinas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    codigo TEXT UNIQUE NOT NULL,
    nome TEXT NOT NULL,
    professor TEXT NOT NULL,
    horario TEXT NOT NULL,
    visivel INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS notas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario TEXT NOT NULL,
    disciplina TEXT NOT NULL,
    media REAL NOT NULL,
    faltas INTEGER NOT NULL,
    situacao TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mural (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    autor TEXT NOT NULL,
    mensagem TEXT NOT NULL,
    criado_em TEXT NOT NULL
);
"""

_USUARIOS_INICIAIS = (
    ("admin", "fatec2026", "Coordenação ADS", "coordenacao", "000001"),
    ("aluno.ads", "siga1234", "Aluno Demonstração ADS", "aluno", "1840482412001"),
    ("prof.si", "seguranca5", "Docente Segurança da Informação", "professor", "000105"),
)

_DISCIPLINAS_INICIAIS = (
    ("ISI002", "Segurança da Informação", "Prof. Segurança", "Segunda 19h00 - 22h30", 1),
    ("IES300", "Engenharia de Software III", "Prof. Engenharia", "Terça 19h00 - 22h30", 1),
    ("ILP508", "Programação Linear e Aplicações", "Prof. Matemática", "Quarta 19h00 - 22h30", 1),
    ("IRC008", "Redes de Computadores", "Prof. Redes", "Quinta 19h00 - 22h30", 1),
    ("TTG001", "Trabalho de Graduação I", "Orientador TG", "Sexta 19h00 - 20h40", 1),
    (
        "ADM999",
        "Auditoria Interna SIGA (Restrito)",
        "TI Diretoria",
        "Registro interno - token: FATEC{sqli_laboratorio}",
        0,
    ),
)

_NOTAS_INICIAIS = (
    ("aluno.ads", "ISI002 - Segurança da Informação", 9.2, 2, "Em curso"),
    ("aluno.ads", "IES300 - Engenharia de Software III", 8.5, 4, "Em curso"),
    ("aluno.ads", "IRC008 - Redes de Computadores", 8.8, 0, "Em curso"),
    ("admin", "Painel Geral ADS - 5º Semestre", 10.0, 0, "Ativo"),
    ("prof.si", "ISI002 - Diário de Classe", 10.0, 0, "Ativo"),
)

_MURAL_INICIAL = (
    (
        "Secretaria Acadêmica",
        "Prazo para entrega de requerimentos de matrícula e aproveitamento até sexta-feira.",
        "01/11/2026 18:30",
    ),
    (
        "Coordenação ADS",
        "Apresentações dos projetos práticos de Segurança da Informação na semana de 06/11.",
        "02/11/2026 14:00",
    ),
)


def inicializar_banco(caminho=CAMINHO_DB_PADRAO):
    """Cria tabelas e insere dados iniciais caso o banco ainda esteja vazio."""
    Path(caminho).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(caminho) as con:
        con.executescript(_SCHEMA)
        con.executemany(
            "INSERT OR IGNORE INTO usuarios (usuario, senha, nome, perfil, ra) VALUES (?, ?, ?, ?, ?)",
            _USUARIOS_INICIAIS,
        )
        con.executemany(
            "INSERT OR IGNORE INTO disciplinas (codigo, nome, professor, horario, visivel) "
            "VALUES (?, ?, ?, ?, ?)",
            _DISCIPLINAS_INICIAIS,
        )
        if con.execute("SELECT COUNT(*) FROM notas").fetchone()[0] == 0:
            con.executemany(
                "INSERT INTO notas (usuario, disciplina, media, faltas, situacao) VALUES (?, ?, ?, ?, ?)",
                _NOTAS_INICIAIS,
            )
        if con.execute("SELECT COUNT(*) FROM mural").fetchone()[0] == 0:
            con.executemany(
                "INSERT INTO mural (autor, mensagem, criado_em) VALUES (?, ?, ?)",
                _MURAL_INICIAL,
            )
        con.commit()


def autenticar_usuario(caminho, usuario, senha):
    """Valida credenciais de login (consulta parametrizada para isolar o cenário de força bruta)."""
    if not usuario or not senha:
        return None
    with sqlite3.connect(caminho) as con:
        con.row_factory = sqlite3.Row
        linha = con.execute(
            "SELECT usuario, nome, perfil, ra FROM usuarios WHERE usuario = ? AND senha = ?",
            (usuario, senha),
        ).fetchone()
    return dict(linha) if linha else None


def obter_usuario(caminho, usuario):
    with sqlite3.connect(caminho) as con:
        con.row_factory = sqlite3.Row
        linha = con.execute(
            "SELECT usuario, nome, perfil, ra FROM usuarios WHERE usuario = ?",
            (usuario,),
        ).fetchone()
    return dict(linha) if linha else None


def listar_notas(caminho, usuario):
    with sqlite3.connect(caminho) as con:
        con.row_factory = sqlite3.Row
        linhas = con.execute(
            "SELECT disciplina, media, faltas, situacao FROM notas WHERE usuario = ?",
            (usuario,),
        ).fetchall()
    return [dict(l) for l in linhas]


def buscar_disciplinas_vulneravel(caminho, termo):
    """Consulta propositalmente vulnerável a SQL Injection em modo somente leitura.

    A conexão `mode=ro` permite demonstrar tautologias (`' OR 1=1--`) e `UNION SELECT`
    (inclusive com `sqlmap`) sem risco de um `DROP TABLE` inutilizar o laboratório.
    """
    uri_ro = f"{Path(caminho).resolve().as_uri()}?mode=ro"
    sql = (
        "SELECT codigo, nome, professor, horario FROM disciplinas "
        f"WHERE visivel = 1 AND codigo || ' - ' || nome LIKE '%{termo}%' "
        "ORDER BY codigo"
    )
    with sqlite3.connect(uri_ro, uri=True) as con:
        linhas = con.execute(sql).fetchall()
    return [
        {"codigo": l[0], "nome": l[1], "professor": l[2], "horario": l[3]}
        for l in linhas
    ]


def listar_mural(caminho):
    with sqlite3.connect(caminho) as con:
        con.row_factory = sqlite3.Row
        linhas = con.execute(
            "SELECT id, autor, mensagem, criado_em FROM mural ORDER BY id DESC LIMIT 30"
        ).fetchall()
    return [dict(l) for l in linhas]


def publicar_mural(caminho, autor, mensagem, criado_em):
    with sqlite3.connect(caminho) as con:
        con.execute(
            "INSERT INTO mural (autor, mensagem, criado_em) VALUES (?, ?, ?)",
            (autor[:60], mensagem[:400], criado_em),
        )
        con.commit()
