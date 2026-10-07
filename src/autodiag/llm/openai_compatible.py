"""Chat Completions adapter for OpenAI-compatible servers."""

from __future__ import annotations

import json
import time
from typing import Any

import httpx

from autodiag.llm.ollama import ChatResult, OllamaError, parse_json_object


class OpenAICompatibleClient:
    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        timeout: float = 300.0,
        response_format: str = "json_object",
        client: httpx.Client | None = None,
    ) -> None:
        # The base URL includes the API prefix (usually /v1).
        url = httpx.URL(base_url)
        if url.scheme not in {"http", "https"} or not url.host:
            raise ValueError("openai_base_url must be an HTTP(S) API base URL")
        if url.username or url.password or url.query or url.fragment:
            raise ValueError("use openai_api_key for credentials; base URL must have no query")
        self.base_url = base_url.rstrip("/")
        self.response_format = response_format
        self.headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._client = client or httpx.Client(timeout=httpx.Timeout(timeout, connect=10.0))

    def chat_json(
        self,
        model: str,
        messages: list[dict[str, str]],
        *,
        format: dict[str, Any] | None = None,
        temperature: float = 0.1,
    ) -> tuple[dict, ChatResult]:
        messages = [dict(message) for message in messages]
        if format is not None and self.response_format != "json_schema":
            instruction = "\nReturn one JSON object matching this schema:\n" + json.dumps(format)
            if messages and messages[0]["role"] == "system":
                messages[0]["content"] += instruction
            else:
                messages.insert(0, {"role": "system", "content": instruction.strip()})
        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": False,
            "temperature": temperature,
        }
        if self.response_format == "json_schema" and format is not None:
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "assessment", "schema": format},
            }
        elif self.response_format == "json_object":
            body["response_format"] = {"type": "json_object"}
        started = time.monotonic()
        try:
            response = self._client.post(
                f"{self.base_url}/chat/completions", json=body, headers=self.headers
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            # Remote error bodies can echo prompts or credentials; do not persist them.
            raise OllamaError(
                f"OpenAI-compatible endpoint returned HTTP {exc.response.status_code}"
            ) from None
        except httpx.HTTPError as exc:
            raise OllamaError(f"OpenAI-compatible request failed: {type(exc).__name__}") from None
        try:
            data = response.json()
            content = data["choices"][0]["message"]["content"]
            if not isinstance(content, str) or not content.strip():
                raise ValueError("empty content")
            usage = data.get("usage") or {}
            result = ChatResult(
                content=content,
                model=data.get("model") or model,
                url=self.base_url,
                elapsed_ms=int((time.monotonic() - started) * 1000),
                prompt_tokens=usage.get("prompt_tokens"),
                completion_tokens=usage.get("completion_tokens"),
            )
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            raise OllamaError("OpenAI-compatible endpoint returned an invalid completion") from None
        return parse_json_object(content), result
