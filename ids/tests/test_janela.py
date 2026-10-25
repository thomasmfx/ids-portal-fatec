from detectores.janela import ContadorPorIp


def test_avisa_ao_atingir_o_limite():
    contador = ContadorPorIp(limite=3, janela=10)
    assert [contador.registrar("10.0.0.1", agora=t) for t in (0, 1, 2)] == [False, False, True]


def test_ips_sao_contados_separadamente():
    contador = ContadorPorIp(limite=2, janela=10)
    assert not contador.registrar("10.0.0.1", agora=0)
    assert not contador.registrar("10.0.0.2", agora=1)
    assert contador.registrar("10.0.0.1", agora=2)


def test_eventos_fora_da_janela_expiram():
    contador = ContadorPorIp(limite=3, janela=10)
    assert not any(contador.registrar("10.0.0.1", agora=t) for t in (0, 6, 12, 18))


def test_silencio_depois_do_aviso_e_novo_aviso_apos_a_janela():
    contador = ContadorPorIp(limite=2, janela=10)
    resultados = [contador.registrar("10.0.0.1", agora=t) for t in (0, 1, 2, 3, 11, 12)]
    assert resultados == [False, True, False, False, True, False]


def test_distintos_conta_valores_diferentes():
    contador = ContadorPorIp(limite=3, janela=10, distintos=True)
    assert not any(contador.registrar("10.0.0.1", valor=80, agora=t) for t in range(5))
    assert not contador.registrar("10.0.0.1", valor=443, agora=5)
    assert contador.registrar("10.0.0.1", valor=22, agora=6)


def test_esquece_ips_inativos():
    contador = ContadorPorIp(limite=100, janela=10)
    for i in range(50):
        contador.registrar(f"203.0.113.{i}", agora=0)
    contador.registrar("10.0.0.1", agora=20)
    assert list(contador._eventos) == ["10.0.0.1"]
