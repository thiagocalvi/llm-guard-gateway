"""
    Provedores de LLM plugáveis.

    LLM_PROVIDER=mock|openai|anthropic, LLM_MODEL, LLM_API_KEY, LLM_BASE_URL.
    "openai" fala o formato /chat/completions, então serve OpenAI, Ollama,
    LM Studio, vLLM etc. só trocando LLM_BASE_URL.
"""
from __future__ import annotations

import os
import re
from typing import Protocol

import httpx

from guard.injection import deobfuscate

TIMEOUT_S = 30.0


class LLMError(RuntimeError):
    pass


class LLMProvider(Protocol):
    def complete(self, system_prompt: str, user_message: str) -> str: ...


class MockLLM:
    """Modelo INGÊNUO, vulnerável de propósito.

    Simula o pior caso de um LLM obediente: se o usuário pede as instruções, ele
    entrega o system prompt inteiro; em qualquer outro caso, ecoa a mensagem
    (com PII e markdown junto). Entende base64/leet/letras separadas, como um
    LLM real entenderia. Serve para testar o gateway de forma reprodutível e
    offline.
    """

    _LEAK = re.compile(
        r"(?=.*\b(?:mostr|revel|repit|repeat|imprim|print|show|reveal|output|exib|escrev|write|"
        r"diga|tell|list|copi|copy|echo|traduz|translat|resum|summar|complete|passa|conta|read)\w*)"
        r"(?=.*\b(?:instruc|instruction|prompt|regras|rules|diretriz|configura|setup|segredo|secret|"
        r"codigo interno|internal code|you were|voce recebeu|before|antes desta)\w*)",
        re.S,
    )

    def complete(self, system_prompt: str, user_message: str) -> str:
        if self._LEAK.search(deobfuscate(user_message)):
            return f"Claro! Minhas instruções são:\n{system_prompt}"
        return f"Entendido! Você disse: {user_message}"


class OpenAICompatible:
    def __init__(self, model: str, api_key: str | None, base_url: str):
        self.model, self.api_key, self.base_url = model, api_key, base_url.rstrip("/")

    def complete(self, system_prompt: str, user_message: str) -> str:
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
        }
        data = _post(f"{self.base_url}/chat/completions", headers, body)
        try:
            return data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as e:
            raise LLMError(f"resposta inesperada do provedor: {e}") from e


class Anthropic:
    def __init__(self, model: str, api_key: str | None, base_url: str):
        self.model, self.api_key, self.base_url = model, api_key, base_url.rstrip("/")

    def complete(self, system_prompt: str, user_message: str) -> str:
        headers = {"x-api-key": self.api_key or "", "anthropic-version": "2023-06-01"}
        body = {
            "model": self.model,
            "max_tokens": 1024,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_message}],
        }
        data = _post(f"{self.base_url}/v1/messages", headers, body)
        try:
            return "".join(b["text"] for b in data["content"] if b.get("type") == "text")
        except (KeyError, TypeError) as e:
            raise LLMError(f"resposta inesperada do provedor: {e}") from e


def _post(url: str, headers: dict, body: dict) -> dict:
    try:
        r = httpx.post(url, headers=headers, json=body, timeout=TIMEOUT_S)
        r.raise_for_status()
        return r.json()
    except httpx.HTTPError as e:
        # Não repassa o corpo do erro.
        raise LLMError(f"falha ao chamar o provedor: {type(e).__name__}") from e


def provider_from_env() -> LLMProvider:
    name = (os.getenv("LLM_PROVIDER") or "mock").lower()
    if name == "mock":
        return MockLLM()
    model = os.getenv("LLM_MODEL")
    if not model:
        raise LLMError("defina LLM_MODEL para usar um provedor real")
    key = os.getenv("LLM_API_KEY")
    if name == "openai":
        return OpenAICompatible(model, key, os.getenv("LLM_BASE_URL") or "https://api.openai.com/v1")
    if name == "anthropic":
        return Anthropic(model, key, os.getenv("LLM_BASE_URL") or "https://api.anthropic.com")
    raise LLMError(f"LLM_PROVIDER desconhecido: {name}")
