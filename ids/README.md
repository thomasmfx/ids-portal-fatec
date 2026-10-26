# IDS (núcleo e detectores)

O `core.py` é o entrypoint do contêiner `ids`. Ele carrega todo arquivo `detect_*.py` da pasta `detectores/` e roda cada um na sua própria thread. Os alertas que os detectores produzem passam por uma `queue.Queue` e chegam a uma única thread consumidora (`db.py`), que grava no SQLite sem disputa de escrita.

```
detect_portscan ─┐
detect_bruteforce┤
detect_sqli      ├─► fila_alertas (queue.Queue) ─► db.consumir ─► alerts.db ─► dashboard
detect_fuzzing   ┤
detect_dos      ─┘
```

A visão geral do projeto e os contratos entre os componentes estão no [README da raiz](../README.md).

## Como escrever um detector

1. Crie `ids/detectores/detect_<nome>.py`. O core encontra o arquivo sozinho, então não é preciso registrar nada. Arquivos sem o prefixo `detect_`, como os helpers abaixo, não são executados como detector.
2. Exponha `detectar(fila_alertas)`. A função roda em loop infinito (um `sniff()` do Scapy ou a leitura do `access.log`) e nunca retorna.
3. Cada detecção vira um alerta criado por `novo_alerta` e é colocada na fila.

Exemplo de detector de log usando os helpers. Ele alerta quando um IP provoca muitos erros 5xx:

```python
from alerta import novo_alerta
from detectores.access_log import seguir_access_log
from detectores.janela import ContadorPorIp


def detectar(fila_alertas):
    contador = ContadorPorIp(limite=10, janela=30)
    for req in seguir_access_log():
        if req.status >= 500 and contador.registrar(req.ip):
            fila_alertas.put(novo_alerta(
                "Erros 5xx em excesso",      # tipo
                req.ip,                      # ip_origem
                "10 respostas 5xx em 30s",   # descricao
                "T1499",                     # mitre
                "media",                     # severidade: "baixa", "media" ou "alta"
            ))
```

Detectores de rede usam `sniff(filter=..., prn=..., store=False)` do Scapy. O `detect_dos.py` serve de exemplo.

Cada alerta tem estes campos: `timestamp` (ISO 8601, UTC), `tipo`, `ip_origem`, `descricao`, `mitre` e `severidade`.

Se o detector quebrar no import ou não tiver `detectar`, o core registra o erro no log e segue com os outros. Se a função lançar uma exceção durante a execução, o traceback aparece no `docker logs` e os demais detectores continuam rodando.

Se o detector precisar de alguma biblioteca, adicione-a ao `requirements.txt`.

## Helpers para detectores

### `detectores/access_log.py`

- `seguir_access_log()` gera uma `Requisicao` para cada linha nova de `/var/log/vitima/access.log`. Funciona como `tail -f`:
  - começa do fim do arquivo e espera ele existir;
  - reabre o arquivo se a vítima o recriar ou truncar.

  Linhas fora do formato geram um aviso no log e são puladas.
- `Requisicao` tem os campos `ip`, `usuario`, `instante`, `metodo`, `caminho` (URL-encoded, como chegou), `status` (int), `tamanho` (int), `referer` e `user_agent`. Tem também a propriedade `caminho_decodificado`, com `%27`, `+` etc. já convertidos. É nela que um payload como `' OR 1=1` aparece legível.
- `interpretar(linha)` converte uma linha avulsa. Serve para testes.

O formato da linha (Combined Log Format) está definido no [README da raiz](../README.md).

### `detectores/janela.py`

- `ContadorPorIp(limite, janela)`: `registrar(ip)` retorna `True` quando o IP atinge `limite` eventos nos últimos `janela` segundos.
- Com `distintos=True`, `registrar(ip, valor)` conta valores diferentes em vez de eventos, como portas de destino distintas.
- Depois de retornar `True`, o IP fica `janela` segundos em silêncio. Assim um ataque contínuo gera um alerta por janela, e não um por evento.
- IPs inativos são descartados, então IPs forjados não fazem a memória crescer.

Nos dois helpers, o parâmetro `agora` existe para os testes simularem o tempo.

## Contrato do `db.py` (Andrey)

O `db.py` precisa expor `consumir(fila_alertas)`. A função faz `fila_alertas.get()` em loop e grava cada alerta. Quando recebe `None`, ela termina: é o sinal de que o contêiner está parando e não vem mais nada.

Enquanto o `db.py` não existir, o core imprime cada alerta como JSON no stdout, e eles aparecem no `docker logs`.

## Trecho do docker-compose (Henrique)

```yaml
  ids:
    build: ./ids
    network_mode: "service:vitima"   # enxerga o tráfego da vítima
    cap_add: [NET_RAW, NET_ADMIN]    # raw sockets para o Scapy
    volumes:
      - volume_logs:/var/log/vitima:ro
      - volume_db:/data
    depends_on: [vitima]
```

## Detector de DoS (`detectores/detect_dos.py`, T1498)

O detector conta os pacotes TCP com SYN ligado e ACK desligado numa janela deslizante (padrão: 200 SYN em 5 s, nas constantes do topo do arquivo). Quando o limite é atingido:

- se um IP responde por pelo menos metade dos SYN da janela, o alerta aponta esse IP;
- se não, o `ip_origem` sai como `múltiplos (possível IP spoofing)`, que é o que acontece com `hping3 --rand-source`.

Depois de um alerta, o detector fica uma janela inteira sem alertar, para o flood não gerar um alerta por pacote.

Para testar: `hping3 -S --flood -p 80 <ip-da-vitima>` (com `--rand-source` para o caso de IPs forjados).

## Detector de Port Scan (`detectores/detect_portscan.py`, T1046)

O detector observa somente pacotes TCP IPv4 com SYN ativo e ACK inativo, sem reter
pacotes (`store=False`). Para cada IP de origem, conta portas TCP de destino
**distintas** numa janela deslizante. O padrão é 10 portas em 30 s
(`LIMITE_PORTAS` e `JANELA_SEG`); são parâmetros de heurística, não prova de
intrusão. Ao atingir o limite, gera um alerta `Port Scan` com MITRE `T1046` e
permanece em silêncio pelo tamanho da janela.

Ele não analisa tráfego não TCP, pode não detectar scans lentos e pode produzir
falsos positivos para IPs compartilhados ou atrás de NAT. Um SYN representa uma
tentativa de conexão, não uma invasão confirmada. O IDS apenas alerta; ele não
bloqueia tráfego.

## Testes

Os testes usam pytest e ficam em `ids/tests/test_<nome>.py`. O pytest está no `requirements-dev.txt` e entra só no estágio `teste` do Dockerfile, fora da imagem que roda o IDS:

```
docker build --target teste -t ids-teste ids/
docker run --rm ids-teste
```
