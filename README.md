# IDS Portal Fatec

Detector de Intrusão (IDS) escrito em Python para a disciplina de Segurança da Informação (5º semestre de ADS, FATEC Mogi das Cruzes).

O laboratório roda em Docker. Um atacante dispara ferramentas reais (nmap, hydra, sqlmap, gobuster, hping3) contra um "Portal Fatec" vulnerável. O IDS observa a rede e os logs da vítima, e o dashboard mostra os alertas.

## Arquitetura

```
atacante ──ataques──► vitima (Portal Fatec, Flask)
                        │
                        ├── tráfego de rede ──► ids: detectores de rede (Scapy) ──┐
                        └── access.log ───────► ids: detectores de log ───────────┤
                                                                                  ▼
                       dashboard ◄── alerts.db (SQLite) ◄── db.py ◄── fila_alertas
```

O contêiner `ids` compartilha a rede da vítima (`network_mode: "service:vitima"`), por isso enxerga todo pacote que chega a ela. O `access.log` e o `alerts.db` ficam em volumes compartilhados entre os contêineres.

## Estrutura prevista

```
ids-portal-fatec/
├── docker-compose.yml           # Henrique
├── vitima/                      # Matheus
├── dashboard/                   # Enzo
└── ids/
    ├── core.py                  # Thomas: entrypoint, threads e fila
    ├── alerta.py                # novo_alerta(): formato único dos alertas
    ├── db.py                    # Andrey
    ├── detectores/
    │   ├── access_log.py        # helper: leitura do access.log
    │   ├── janela.py            # helper: contagem por IP em janela de tempo
    │   ├── detect_bruteforce.py # Enzo
    │   ├── detect_dos.py        # Thomas
    │   ├── detect_fuzzing.py    # Matheus
    │   ├── detect_portscan.py   # Henrique
    │   └── detect_sqli.py       # Andrey
    └── tests/
```

## Divisão de tarefas

| Integrante | Detector | Componente | MITRE ATT&CK |
|---|---|---|---|
| Enzo Kuwamoto | Força bruta (`detect_bruteforce.py`) | Dashboard | T1110 |
| Henrique Hida | Port scan (`detect_portscan.py`) | Infraestrutura (`docker-compose.yml`) | T1046 |
| Andrey Marques | SQL Injection / XSS (`detect_sqli.py`) | Banco de dados (`ids/db.py`) | T1190 |
| Matheus Schalch | Fuzzing de diretórios (`detect_fuzzing.py`) | Vítima (`vitima/`) | T1595 |
| Thomas Moises | DoS / SYN Flood (`detect_dos.py`) | Núcleo do IDS (`ids/core.py`) | T1498 |

## Contratos entre os componentes

Estes são os pontos em que a parte de um depende da parte de outro. Se algum mudar, avise quem depende dele.

### 1. Vítima → detectores de log: `access.log`

A vítima (Matheus) escreve o arquivo. Os detectores de força bruta, SQLi/XSS e fuzzing leem.

- O arquivo fica em `/var/log/vitima/access.log`, no volume compartilhado `volume_logs`.
- Cada requisição gera uma linha em Combined Log Format, o mesmo do Apache e do Nginx:

  ```
  172.20.0.3 - - [25/Oct/2026:21:00:00 +0000] "GET /admin?id=1 HTTP/1.1" 404 207 "-" "gobuster/3.6"
  ```

  Os campos são, em ordem: IP do cliente, identd (`-`), usuário autenticado (`-` se não houver), data, linha da requisição, status, tamanho da resposta em bytes, Referer e User-Agent.
- O caminho vai como chegou na requisição, ainda URL-encoded (`%27`, `+`).
- Aspas dentro de um campo são escapadas como `\"`.
- Login com senha errada responde com status **401**. É assim que o detector de força bruta reconhece uma tentativa falha.

O parser já existe em `ids/detectores/access_log.py`. Veja o [README do IDS](ids/README.md).

### 2. Detectores → núcleo

Cada detector é um arquivo `ids/detectores/detect_<nome>.py` com uma função `detectar(fila_alertas)`. Os alertas são criados com `novo_alerta(...)`. O passo a passo e um exemplo estão no [README do IDS](ids/README.md).

### 3. Núcleo → `db.py`

O `db.py` (Andrey) expõe `consumir(fila_alertas)`, que lê a fila e para ao receber `None`. Detalhes no [README do IDS](ids/README.md).

### 4. `db.py` → dashboard

O esquema da tabela no SQLite é combinado entre Andrey (`db.py`) e Enzo (dashboard). O arquivo fica no volume compartilhado `volume_db`.

### 5. docker-compose

O `docker-compose.yml` é do Henrique. Os requisitos do contêiner `ids` (rede compartilhada, capabilities e volumes) estão no [README do IDS](ids/README.md).

## Como rodar

Depois que o `docker-compose.yml` existir:

```
docker compose up --build
```

Cada componente documenta os próprios testes no seu README.
