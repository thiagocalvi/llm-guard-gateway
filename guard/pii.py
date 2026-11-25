"""
    Detecção e mascaramento de dados pessoais (LGPD).

    Validar dígito verificador / Luhn: sem isso, qualquer sequência de 11 dígitos
    (protocolo, número de pedido) viraria "CPF" e o bot mascararia dado que não é pessoal.
    A validação derruba a maioria desses falsos positivos.
"""
import re

EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
CNPJ = re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b")
CPF = re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b")
CARD = re.compile(r"\b(?:\d{4}[ -]?){3}\d{1,7}\b")
PHONE = re.compile(r"(?:\+?55[\s-]?)?(?:\([1-9]\d\)|\b[1-9]\d)[\s-]?9?\d{4}[\s-]?\d{4}\b")


def _digits(s: str) -> list[int]:
    return [int(c) for c in s if c.isdigit()]


def valid_cpf(s: str) -> bool:
    d = _digits(s)
    if len(d) != 11 or len(set(d)) == 1:  # 111.111.111-11 passa no cálculo mas é inválido
        return False
    for n in (9, 10):
        dv = sum(d[i] * (n + 1 - i) for i in range(n)) * 10 % 11 % 10
        if dv != d[n]:
            return False
    return True


def valid_cnpj(s: str) -> bool:
    d = _digits(s)
    if len(d) != 14 or len(set(d)) == 1:
        return False
    w1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    for n, w in ((12, w1), (13, [6] + w1)):
        r = sum(a * b for a, b in zip(d[:n], w)) % 11
        if (0 if r < 2 else 11 - r) != d[n]:
            return False
    return True


def valid_luhn(s: str) -> bool:
    d = _digits(s)[::-1]
    if not 13 <= len(d) <= 19:
        return False
    total = sum(x if i % 2 == 0 else (x * 2 - 9 if x > 4 else x * 2) for i, x in enumerate(d))
    return total % 10 == 0


# e-mail primeiro (pode conter dígitos) e CNPJ antes de cartão
# (14 dígitos podem passar no Luhn por acaso). Cada etapa roda sobre o texto já
# mascarado, então um trecho nunca é contado duas vezes.
_RULES = [
    ("EMAIL", EMAIL, None),
    ("CNPJ", CNPJ, valid_cnpj),
    ("CPF", CPF, valid_cpf),
    ("CARTAO", CARD, valid_luhn),
    ("TELEFONE", PHONE, None),
]


def mask_pii(text: str) -> tuple[str, list[str]]:
    """Devolve (texto mascarado, tipos encontrados). Ex.: '[CPF]' no lugar do número."""
    found: list[str] = []
    for kind, pattern, validator in _RULES:
        def repl(m: re.Match) -> str:
            if validator and not validator(m.group()):
                return m.group()
            found.append(kind)
            return f"[{kind}]"
        text = pattern.sub(repl, text)
    return text, found


def find_pii(text: str) -> list[str]:
    return mask_pii(text)[1]
