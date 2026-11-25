"""API HTTP do gateway. Rodar: uvicorn app:app --reload"""
import os

from fastapi import FastAPI
from pydantic import BaseModel

from guard.audit import AuditLog
from guard.gateway import DEFAULT_SYSTEM_PROMPT, Gateway
from guard.llm import provider_from_env

app = FastAPI(title="llm-guard-gateway")
gateway = Gateway(
    provider=provider_from_env(),
    system_prompt=os.getenv("SYSTEM_PROMPT") or DEFAULT_SYSTEM_PROMPT,
    audit=AuditLog(os.getenv("AUDIT_LOG") or "logs/audit.jsonl"),
)


class ChatIn(BaseModel):
    message: str
    # user_id vem do cliente; atrás de autenticação real, usar o id da sessão.
    user_id: str = "anon"


class ChatOut(BaseModel):
    reply: str
    blocked: bool
    stage: str


@app.post("/chat", response_model=ChatOut)
def chat(body: ChatIn) -> ChatOut:
    r = gateway.handle(body.message, body.user_id)
    # Motivos e score ficam só no log.
    return ChatOut(reply=r.reply, blocked=r.blocked, stage=r.stage)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
