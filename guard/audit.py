"""
    Log de auditoria em JSON Lines.

    Minimização de dados: o log guarda só o HASH da mensagem. O hash permite correlacionar
    repetições do mesmo ataque sem expor dados pessoais ou sigilosos.
"""
import hashlib
import json
import logging
import time
from pathlib import Path

logger = logging.getLogger("guard.audit")

def short_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


class AuditLog:
    def __init__(self, path: str | Path | None = "logs/audit.jsonl"):
        self.path = Path(path) if path else None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, **event) -> dict:
        event = {"ts": round(time.time(), 3), **event}
        line = json.dumps(event, ensure_ascii=False)
        logger.info(line)
        if self.path:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        return event
