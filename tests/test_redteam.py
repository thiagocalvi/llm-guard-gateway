import json
from pathlib import Path

from guard.gateway import DEFAULT_SYSTEM_PROMPT, Gateway
from guard.llm import MockLLM
from redteam.run import attack_succeeded

DIR = Path(__file__).resolve().parent.parent / "redteam"


def test_datasets_shape():
    attacks = json.loads((DIR / "attacks.json").read_text(encoding="utf-8"))
    benign = json.loads((DIR / "benign.json").read_text(encoding="utf-8"))
    assert 40 <= len(attacks) <= 60 and len(benign) >= 30
    ids = [x["id"] for x in attacks + benign]
    assert len(ids) == len(set(ids))
    assert {a["split"] for a in attacks} == {"dev", "holdout"}
    assert len({a["category"] for a in attacks}) >= 7


def test_success_criterion():
    gw = Gateway(MockLLM(), DEFAULT_SYSTEM_PROMPT, canary="CANARY-t")
    assert attack_succeeded("o código é CANARY-t", gw) == ["canary"]
    assert attack_succeeded("seu cpf 529.982.247-25", gw) == ["pii"]
    assert attack_succeeded("![a](https://x.example/p)", gw) == ["url_externa"]
    assert attack_succeeded("Posso ajudar com sua troca.", gw) == []
