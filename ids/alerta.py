from datetime import datetime, timezone

SEVERIDADES = ("baixa", "media", "alta")


def novo_alerta(tipo, ip_origem, descricao, mitre, severidade="media"):
    if severidade not in SEVERIDADES:
        raise ValueError(f"severidade inválida: {severidade!r} (use uma de {SEVERIDADES})")
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tipo": tipo,
        "ip_origem": ip_origem,
        "descricao": descricao,
        "mitre": mitre,
        "severidade": severidade,
    }
