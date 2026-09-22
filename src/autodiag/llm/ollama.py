"""Minimal Ollama client: ``/api/chat`` with structured output, primary/fallback endpoints,
health cache. Used by the diagnosis assessor; nothing else in AutoDiag needs a model."""

from __future__ import annotations

import json
import re
import time
from typing import Any

import httpx
from pydantic import BaseModel


class OllamaError(RuntimeError):
    pass


class ChatResult(BaseModel):
    content: str
    model: str
    url: str
    elapsed_ms: int
    prompt_tokens: int | None = None
    completion_tokens: int | None = None


_FENCE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.MULTILINE)


class OllamaClient:
    def __init__(
        self,
        primary_url: str,
        fallback_url: str | None = None,
        *,
        timeout: float = 300.0,
        num_ctx: int = 32768,
        health_cache_seconds: float = 30.0,
        client: httpx.Client | None = None,
    ) -> None:
        self.urls = [u.rstrip("/") for u in (primary_url, fallback_url) if u]
        self.timeout = timeout
        self.num_ctx = num_ctx
        self.health_cache_seconds = health_cache_seconds
        self._client = client or httpx.Client(timeout=httpx.Timeout(timeout, connect=10.0))
        self._health: dict[str, tuple[float, bool]] = {}

    # -- health ------------------------------------------------------------------------
    def healthy(self, url: str) -> bool:
        cached = self._health.get(url)
        now = time.monotonic()
        if cached and now - cached[0] < self.health_cache_seconds:
            return cached[1]
        try:
            ok = self._client.get(f"{url}/api/tags", timeout=10.0).status_code == 200
        except httpx.HTTPError:
            ok = False
        self._health[url] = (now, ok)
        return ok

    def available_url(self) -> str | None:
        return next((u for u in self.urls if self.healthy(u)), None)

    def models(self, url: str | None = None) -> list[str]:
        u = url or self.available_url()
        if u is None:
            return []
        try:
            data = self._client.get(f"{u}/api/tags", timeout=10.0).json()
        except (httpx.HTTPError, ValueError):
            return []
        return [m.get("name", "") for m in data.get("models", [])]

    # -- chat --------------------------------------------------------------------------
    def chat(
        self,
        model: str,
        messages: list[dict[str, str]],
        *,
        format: dict[str, Any] | str | None = None,
        temperature: float = 0.1,
        think: bool = False,
        num_predict: int | None = None,
        keep_alive: str = "10m",
    ) -> ChatResult:
        errors: list[str] = []
        for url in self.urls:
            if not self.healthy(url):
                errors.append(f"{url}: unreachable")
                continue
            body: dict[str, Any] = {
                "model": model,
                "messages": messages,
                "stream": False,
                "think": think,
                "keep_alive": keep_alive,
                "options": {"num_ctx": self.num_ctx, "temperature": temperature},
            }
            if format is not None:
                body["format"] = format
            if num_predict:
                body["options"]["num_predict"] = num_predict
            started = time.monotonic()
            try:
                r = self._client.post(f"{url}/api/chat", json=body)
                if r.status_code >= 400:
                    errors.append(f"{url}: HTTP {r.status_code} {r.text[:200]}")
                    continue
                data = r.json()
            except (httpx.HTTPError, ValueError) as exc:
                errors.append(f"{url}: {type(exc).__name__}: {exc}")
                continue
            msg = data.get("message") or {}
            return ChatResult(
                content=str(msg.get("content", "")),
                model=str(data.get("model", model)),
                url=url,
                elapsed_ms=int((time.monotonic() - started) * 1000),
                prompt_tokens=data.get("prompt_eval_count"),
                completion_tokens=data.get("eval_count"),
            )
        raise OllamaError("no Ollama endpoint answered: " + "; ".join(errors))

    def chat_json(
        self, model: str, messages: list[dict[str, str]], **kw: Any
    ) -> tuple[dict, ChatResult]:
        res = self.chat(model, messages, **kw)
        return parse_json_object(res.content), res


def parse_json_object(content: str) -> dict:
    """Parse a JSON object from model output, tolerating code fences and stray prose."""
    text = _FENCE.sub("", content).strip()
    try:
        obj = json.loads(text)
    except ValueError:
        start, end = text.find("{"), text.rfind("}")
        if start < 0 or end <= start:
            raise OllamaError(f"model did not return JSON: {content[:200]!r}") from None
        try:
            obj = json.loads(text[start : end + 1])
        except ValueError as exc:
            raise OllamaError(f"model returned invalid JSON: {exc}") from None
    if not isinstance(obj, dict):
        raise OllamaError("model returned JSON that is not an object")
    return obj
