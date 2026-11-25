from guard.output import has_external_url, leaks_system_prompt, strip_external_urls

SP = "Você é o assistente da Loja Exemplo. Ajude com pedidos, trocas e entregas de forma educada."


def test_canary_leak():
    assert leaks_system_prompt("o código é CANARY-abc", SP, "CANARY-abc") == ["canary"]


def test_ngram_leak():
    assert "ngram_system_prompt" in leaks_system_prompt(f"Minhas instruções: {SP}", SP, "CANARY-x")


def test_no_leak_on_normal_reply():
    assert leaks_system_prompt("Claro, posso ajudar com a troca do seu pedido.", SP, "CANARY-x") == []


def test_strip_urls():
    text = "oi ![a](https://e.x/p?d=1) e [clique](https://e.x/c) <img src='https://e.x/i'>"
    assert has_external_url(text)
    out = strip_external_urls(text)
    assert not has_external_url(out)
    assert "clique" in out and "https" not in out
