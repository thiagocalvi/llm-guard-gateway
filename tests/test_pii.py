import pytest

from guard.pii import find_pii, mask_pii, valid_cnpj, valid_cpf, valid_luhn


@pytest.mark.parametrize("text,kind", [
    ("meu cpf é 529.982.247-25", "CPF"),
    ("cpf 52998224725", "CPF"),
    ("cnpj 11.222.333/0001-81", "CNPJ"),
    ("cartão 4111 1111 1111 1111", "CARTAO"),
    ("email joao.silva@example.com", "EMAIL"),
    ("ligue (11) 98765-4321", "TELEFONE"),
    ("ligue +55 21 99876-5432", "TELEFONE"),
])
def test_detects(text, kind):
    assert find_pii(text) == [kind]


@pytest.mark.parametrize("text", [
    "protocolo 123.456.789-00",      # formato de CPF, DV inválido
    "código 111.111.111-11",         # dígitos repetidos
    "pedido 98765432101",
    "rastreio BR123456789BR",
    "cartão 4111 1111 1111 1112",    # falha no Luhn
])
def test_ignores_lookalikes(text):
    assert find_pii(text) == []


def test_mask_replaces_value():
    masked, kinds = mask_pii("CPF 529.982.247-25 e email a@b.com")
    assert masked == "CPF [CPF] e email [EMAIL]"
    assert kinds == ["EMAIL", "CPF"]


def test_validators():
    assert valid_cpf("529.982.247-25") and not valid_cpf("529.982.247-26")
    assert valid_cnpj("11222333000181") and not valid_cnpj("11222333000182")
    assert valid_luhn("5555555555554444") and not valid_luhn("5555555555554445")
