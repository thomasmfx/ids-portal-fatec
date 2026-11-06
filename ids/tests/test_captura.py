from types import SimpleNamespace

import pytest

from detectores import captura, detect_dos, detect_portscan


def test_reune_interfaces_das_rotas_sem_loopback_ou_repeticoes(monkeypatch):
    rotas = [(0, 0, "", "eth1"), (0, 0, "", "eth0"), (0, 0, "", "eth1"), (0, 0, "", "lo")]
    monkeypatch.setattr(captura, "conf", SimpleNamespace(route=SimpleNamespace(routes=rotas), loopback_name="lo"))
    assert captura.interfaces_captura() == ["eth0", "eth1"]


def test_falha_explicita_sem_interface_de_rede(monkeypatch):
    monkeypatch.setattr(captura, "conf", SimpleNamespace(route=SimpleNamespace(routes=[]), loopback_name="lo"))
    with pytest.raises(RuntimeError, match="nenhuma interface"):
        captura.interfaces_captura()


@pytest.mark.parametrize("modulo", [detect_dos, detect_portscan])
def test_detector_captura_todas_as_interfaces(monkeypatch, modulo):
    chamadas = []
    monkeypatch.setattr(modulo, "interfaces_captura", lambda: ["eth0", "eth1"])
    monkeypatch.setattr(modulo, "sniff", lambda **kwargs: chamadas.append(kwargs))
    modulo.detectar(None)
    assert chamadas[0]["iface"] == ["eth0", "eth1"]
    assert chamadas[0]["store"] is False
