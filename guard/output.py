"""
    Filtro de saída: olha o que o LLM respondeu.

    O detector de entrada nunca terá recall de 100%. Mesmo que um ataque passe,
    ele só "vence" se o segredo sair, a verificação é determinística: o canary é
    uma string aleatória que nunca apareceria por acaso.
"""
import re

from guard.injection import normalize

NGRAM = 5
# 3 trechos de 5 palavras iguais ao system prompt: uma frase comum coincide em 1, despejar o prompt coincide em dezenas.
LEAK_MIN_NGRAMS = 3

# Imagem markdown/HTML é buscada automaticamente pelo cliente que renderiza a
# resposta: a URL vira canal de exfiltração sem o usuário clicar em nada.
MD_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*https?://[^)]*\)")
HTML_IMG = re.compile(r"<img[^>]*src\s*=\s*['\"]?https?://[^>]*>", re.I)
MD_LINK = re.compile(r"\[([^\]]*)\]\(\s*https?://[^)]*\)")


def _ngrams(text: str) -> set[tuple[str, ...]]:
    words = re.findall(r"\w+", normalize(text))
    return {tuple(words[i:i + NGRAM]) for i in range(len(words) - NGRAM + 1)}


def leaked_ngrams(reply: str, system_prompt: str) -> int:
    return len(_ngrams(reply) & _ngrams(system_prompt))


def leaks_system_prompt(reply: str, system_prompt: str, canary: str) -> list[str]:
    reasons = []
    if canary and canary.lower() in reply.lower():
        reasons.append("canary")
    if leaked_ngrams(reply, system_prompt) >= LEAK_MIN_NGRAMS:
        reasons.append("ngram_system_prompt")
    return reasons


def has_external_url(reply: str) -> bool:
    return bool(MD_IMAGE.search(reply) or HTML_IMG.search(reply) or MD_LINK.search(reply))


def strip_external_urls(reply: str) -> str:
    # shortcut: remove todo link externo; se o bot precisar mandar links, criar allowlist de domínios.
    reply = MD_IMAGE.sub("[imagem removida]", reply)
    reply = HTML_IMG.sub("[imagem removida]", reply)
    return MD_LINK.sub(r"\1", reply)
