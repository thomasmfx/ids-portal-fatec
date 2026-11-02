# Vítima — Portal Fatec (Flask)

Aplicação web vulnerável simulando o Portal Acadêmico da FATEC Mogi das Cruzes. Ela serve de alvo para os ataques do laboratório e grava todas as requisições HTTP em `/var/log/vitima/access.log` (volume compartilhado `volume_logs`), no formato **Combined Log Format** lido pelos detectores do IDS.

## Rotas expostas e relação com os ataques

| Rota | Métodos | Comportamento | Ataque / Detector associado |
|---|---|---|---|
| `/` | `GET` | Página inicial do Portal Acadêmico, busca rápida e avisos | Tráfego legítimo |
| `/login` | `GET`, `POST` | Autenticação via formulário HTML, JSON ou Basic Auth. Credenciais erradas respondem **`401`**; corretas respondem **`200`** | Força bruta (`Hydra` → `detect_bruteforce.py`, `T1110`) |
| `/painel`, `/boletim` | `GET` | Boletim do usuário autenticado (`200`) ou `401` sem sessão | Pós-autenticação |
| `/logout` | `GET` | Encerra a sessão atual | Tráfego legítimo |
| `/busca?q=...` | `GET` | Busca de disciplinas propositalmente vulnerável a SQL Injection (em conexão SQLite `mode=ro`) e XSS refletido | SQLi / XSS (`sqlmap` → `detect_sqli.py`, `T1190`) |
| `/mural` | `GET`, `POST` | Mural público de recados acadêmicos | Navegação / testes HTTP |
| `/secretaria`, `/robots.txt` | `GET` | Páginas descobertas em enumeração de diretórios (`200`) | Fuzzing (`gobuster`/`dirb` → `detect_fuzzing.py`, `T1595`) |
| `/admin` | `GET` | Diretório restrito (`403`) | Fuzzing (`T1595`) |
| `/<inexistente>` | qualquer | Retorna página `404` e registra no `access.log` | Fuzzing (`detect_fuzzing.py`, `T1595`) |
| `/health` | `GET` | Verificação de saúde (`{"status": "ok"}`) | Infraestrutura |

### Credenciais fictícias cadastradas no laboratório

- `admin` / `fatec2026`
- `aluno.ads` / `siga1234`
- `prof.si` / `seguranca5`

## Contrato do `access.log`

Toda resposta HTTP passa pelo hook `after_request` (`vitima/access_log.py`) e gera uma linha em `/var/log/vitima/access.log`:

```text
172.20.0.3 - - [25/Oct/2026:21:00:00 +0000] "GET /busca?q=%27+OR+1%3D1-- HTTP/1.1" 200 512 "-" "sqlmap/1.8"
```

- O caminho e a query string são gravados **ainda URL-encoded** (`%27`, `+`, `%3C`), exatamente como recebidos.
- Aspas (`"`), barras (`\`) e quebras de linha dentro dos campos entre aspas são escapadas (`\"`, `\\`, `\n`).
- Cada escrita faz `flush()` imediato para que o `seguir_access_log()` do IDS receba o evento em tempo real.

## Variáveis de ambiente opcionais

- `VITIMA_ACCESS_LOG`: caminho do arquivo de log (padrão: `/var/log/vitima/access.log`).
- `VITIMA_DB_PATH`: caminho do SQLite interno do portal (padrão: `/tmp/portal_fatec.db`).
- `PORT`: porta ao executar `python app.py` diretamente (padrão: `5000`).

## Testes

Com Docker (mesmo padrão do `ids/`):

```bash
docker build --target teste -t vitima-teste vitima/
docker run --rm vitima-teste
```

Ou localmente com `pytest`:

```bash
cd vitima
pytest -v
```
