import json

import httpx
import pytest

from autodiag.core.settings import Settings
from autodiag.diagnose.engine import default_assessor
from autodiag.llm.ollama import OllamaError
from autodiag.llm.openai_compatible import OpenAICompatibleClient


@pytest.mark.parametrize("mode", ["json_object", "json_schema", "none"])
@pytest.mark.parametrize("key", [None, "test-secret"])
def test_request_and_usage(mode, key):
    def handle(request):
        assert str(request.url) == "http://local/custom/v1/chat/completions"
        assert request.headers.get("authorization") == (f"Bearer {key}" if key else None)
        body = json.loads(request.content)
        assert body["model"] == "advisor"
        assert "options" not in body and "think" not in body
        if mode == "none":
            assert "response_format" not in body
        else:
            assert body["response_format"]["type"] == mode
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": '{"headline": "ok"}'}}],
                "usage": {"prompt_tokens": 12, "completion_tokens": 4},
            },
        )

    client = OpenAICompatibleClient(
        "http://local/custom/v1/",
        api_key=key,
        response_format=mode,
        client=httpx.Client(transport=httpx.MockTransport(handle)),
    )
    data, result = client.chat_json("advisor", [], format={"type": "object"})
    assert data == {"headline": "ok"}
    assert result.prompt_tokens == 12 and result.completion_tokens == 4


@pytest.mark.parametrize("payload", [{}, {"choices": []}, {"choices": None}, []])
def test_malformed_completion(payload):
    client = OpenAICompatibleClient(
        "http://local/v1",
        client=httpx.Client(
            transport=httpx.MockTransport(lambda request: httpx.Response(200, json=payload))
        ),
    )
    with pytest.raises(OllamaError, match="invalid completion"):
        client.chat_json("advisor", [])


def test_http_error_does_not_leak_response():
    client = OpenAICompatibleClient(
        "http://local/v1",
        client=httpx.Client(
            transport=httpx.MockTransport(lambda request: httpx.Response(401, text="test-secret"))
        ),
    )
    with pytest.raises(OllamaError, match="HTTP 401") as error:
        client.chat_json("advisor", [])
    assert "test-secret" not in str(error.value)


def test_provider_selection(monkeypatch, tmp_path):
    monkeypatch.setenv("AUTODIAG_CONFIG", str(tmp_path / "missing"))
    settings = Settings(
        _env_file=None, llm_provider="openai", openai_model="custom", openai_api_key="test-secret"
    )
    assessor = default_assessor(settings)
    assert isinstance(assessor.client, OpenAICompatibleClient)
    assert assessor.model == "custom"
    assert default_assessor(settings, model="override").model == "override"
    assert "test-secret" not in repr(settings)
