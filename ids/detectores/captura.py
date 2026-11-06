"""Seleção das interfaces IPv4 para os detectores de rede."""

from scapy.all import conf


def interfaces_captura():
    # Cada rede Docker conectada à vítima tem sua própria rota e interface.
    interfaces = sorted({rota[3] for rota in conf.route.routes if rota[3] != conf.loopback_name})
    if not interfaces:
        raise RuntimeError("nenhuma interface IPv4 disponível para captura")
    return interfaces
