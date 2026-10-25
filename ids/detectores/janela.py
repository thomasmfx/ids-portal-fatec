import time
from collections import Counter, defaultdict, deque


class ContadorPorIp:
    """Avisa quando um IP atinge `limite` eventos nos últimos `janela` segundos.

    Com distintos=True conta valores diferentes (ex.: portas de destino) em vez de eventos.
    Depois de avisar, o IP fica `janela` segundos em silêncio, para não gerar um alerta por evento.
    """

    def __init__(self, limite, janela, distintos=False):
        self.limite = limite
        self.janela = janela
        self.distintos = distintos
        self._eventos = defaultdict(deque)  # ip -> (instante, valor)
        self._valores = defaultdict(Counter)  # ip -> ocorrências de cada valor dentro da janela
        self._silencio_ate = {}
        self._ultima_limpeza = float("-inf")

    def registrar(self, ip, valor=None, agora=None):
        agora = time.monotonic() if agora is None else agora
        eventos, valores = self._eventos[ip], self._valores[ip]
        eventos.append((agora, valor))
        valores[valor] += 1
        while eventos[0][0] <= agora - self.janela:
            _, antigo = eventos.popleft()
            valores[antigo] -= 1
            if not valores[antigo]:
                del valores[antigo]

        if agora - self._ultima_limpeza >= self.janela:
            self._limpar(agora)

        total = len(valores) if self.distintos else len(eventos)
        if total < self.limite or agora < self._silencio_ate.get(ip, float("-inf")):
            return False
        self._silencio_ate[ip] = agora + self.janela
        return True

    def _limpar(self, agora):
        # IPs forjados (hping3 --rand-source) aparecem uma vez e nunca mais; sem isso a memória só cresce
        for ip in [ip for ip, eventos in self._eventos.items() if eventos[-1][0] <= agora - self.janela]:
            del self._eventos[ip], self._valores[ip]
            self._silencio_ate.pop(ip, None)
        self._ultima_limpeza = agora
