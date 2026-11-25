import json

from guard.audit import AuditLog, short_hash
from guard.ratelimit import RateLimiter


def test_rate_limit_window():
    now = [0.0]
    rl = RateLimiter(max_requests=2, window_s=10, clock=lambda: now[0])
    assert rl.allow("u") and rl.allow("u") and not rl.allow("u")
    assert rl.allow("outro")
    now[0] = 10.0
    assert rl.allow("u")


def test_audit_never_stores_plaintext(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    log.record(msg_hash=short_hash("meu cpf 529.982.247-25"))
    line = (tmp_path / "a.jsonl").read_text()
    assert "529" not in line
    assert json.loads(line)["msg_hash"] == short_hash("meu cpf 529.982.247-25")
