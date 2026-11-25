"""
    Detector de prompt injection por regras ponderadas (PT/EN).

    Por que regras: são auditáveis (cada bloqueio diz qual regra disparou), não exigem dados
    de treino e rodam rápido. O custo é recall limitado contra paráfrases, por isso
    é só uma camada; o filtro de saída existe justamente para pegar o que passar daqui.
"""
import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

THRESHOLD = 0.5

# Caracteres de largura zero são usados para quebrar palavras-chave ("ig​nore").
_INVISIBLE = re.compile(r"[­​-‏⁠-⁤﻿]")
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
# "i g n o r e" / "r-e-v-e-l-e": letras isoladas separadas por 1 caractere.
_SPACED = re.compile(r"(?<!\w)(?:\w[ .\-_*]){2,}\w(?!\w)")
_LEET = str.maketrans("013457@$", "oieastas")

_VERB_OVERRIDE = r"(?:ignor\w*|desconsider\w*|esquec\w*|esqueca|disregard|forget|override|bypass)"
_QUALIFIER = r"(?:anterior\w*|previous|prior|above|acima|tod[ao]s?|all|suas|seus|your|iniciais|initial|original\w*|sistema|system)"
_TARGET = r"(?:instruc\w*|instruction\w*|regras?|rules?|orientac\w*|prompt|diretriz\w*|guidelines?|restric\w*)"
_REVEAL = r"(?:mostr\w*|revel\w*|repit\w*|repeat|imprim\w*|print|show|reveal|output|exib\w*|escrev\w*|write|diga|tell|list\w*|copi\w*|copy|echo|traduz\w*|translate|resum\w*|summari[sz]e)"

# (nome, peso, regex). Os pesos foram calibrados no conjunto "dev" do redteam/.
RULES = [
    ("override_instrucoes", 0.6,
     re.compile(rf"\b{_VERB_OVERRIDE}\b(?=.{{0,80}}\b{_TARGET})(?=.{{0,80}}\b{_QUALIFIER}\b)")),
    ("pedido_system_prompt", 0.6,
     re.compile(rf"\b{_REVEAL}\b.{{0,60}}(?:system prompt|prompt do sistema|(?:suas|your|initial|iniciais|hidden|secret\w*|internal|internas)\s+{_TARGET}|{_TARGET}\s+(?:iniciais|do sistema|internas|secretas|originais))")),
    ("jailbreak_conhecido", 0.5,
     re.compile(r"\b(?:dan|do anything now|developer mode|modo desenvolvedor|jailbr\w*|sem restric\w*|sem filtros?|without (?:any )?restrictions|no restrictions|unfiltered)\b")),
    ("troca_de_persona", 0.3,
     re.compile(r"\b(?:voce agora e|a partir de agora voce|you are now|from now on you|finja que|pretend (?:to be|you are)|aja como|act as|stay in character)\b")),
    ("marcador_falso_de_sistema", 0.5,
     re.compile(r"(?:\[system\]|<\|?system\|?>|#{2,}\s*system|nova instrucao do sistema|new (?:system )?instructions? from|admin override|modo de manutencao)")),
    ("segredo_interno", 0.3,
     re.compile(r"\b(?:codigo interno|internal code|secret code|codigo secreto|chave secreta|api key)\b")),
    ("exfiltracao_markdown", 0.5,
     re.compile(r"!\[[^\]]*\]\(\s*https?://|<img[^>]+src\s*=\s*['\"]?https?://")),
]


@dataclass
class InjectionResult:
    score: float
    reasons: list[str] = field(default_factory=list)

    @property
    def is_injection(self) -> bool:
        return self.score >= THRESHOLD


def _fold(text: str) -> str:
    """Minúsculas, sem acento, sem invisíveis (espaços intactos)."""
    text = unicodedata.normalize("NFKD", _INVISIBLE.sub("", text))
    return "".join(c for c in text if not unicodedata.combining(c)).lower()


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", _fold(text)).strip()


def _decode_base64(text: str) -> list[str]:
    out = []
    for token in _B64.findall(text):
        try:
            decoded = base64.b64decode(token + "=" * (-len(token) % 4), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            continue
        if decoded.isprintable():
            out.append(decoded)
    return out


def deobfuscate(text: str) -> str:
    """Texto normalizado + variantes desofuscadas, concatenadas.

    As regras rodam sobre tudo junto: assim o texto original continua sendo
    analisado e as variantes só adicionam sinais (leet aplicado em texto normal
    não cria falso positivo novo porque as regras exigem palavras inteiras).
    """
    base = normalize(text)
    # Antes de colapsar espaços: em "i g n o r e  a s" o espaço duplo é o que separa as palavras.
    spaced = normalize(_SPACED.sub(lambda m: re.sub(r"[ .\-_*]", "", m.group()), _fold(text)))
    variants = [base, spaced]
    variants.append(variants[-1].translate(_LEET))
    # base64 decodificado do texto original (normalizar mudaria maiúsculas e quebraria o b64).
    variants += [normalize(d) for d in _decode_base64(_INVISIBLE.sub("", text))]
    return "\n".join(variants)


def detect_injection(text: str) -> InjectionResult:
    analyzed = deobfuscate(text)
    reasons = [name for name, _, rx in RULES if rx.search(analyzed)]
    score = sum(w for name, w, _ in RULES if name in reasons)
    if _INVISIBLE.search(text) or len(analyzed.split("\n")) > 3:
        # Ofuscação sozinha não prova ataque, mas soma ao que já foi visto.
        reasons.append("ofuscacao")
        score += 0.2
    return InjectionResult(score=round(min(score, 1.0), 2), reasons=reasons)
