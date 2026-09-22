from pathlib import Path

from autodiag.core.settings import Settings, load_settings


def test_defaults_are_loopback_and_generic(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AUTODIAG_CONFIG", str(tmp_path / "missing.toml"))
    s = load_settings(env_file=None)
    assert s.listen_host == "127.0.0.1"
    assert s.listen_port == 8790
    assert s.ollama_primary_url == "http://127.0.0.1:11434"
    assert s.ollama_num_ctx == 32768
    assert s.redact_for_llm is True
    assert s.tool_max_lines == 200
    assert s.tool_max_lines_hard_cap == 1000
    assert s.tool_max_bytes == 16384


def test_env_overrides_defaults(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AUTODIAG_CONFIG", str(tmp_path / "missing.toml"))
    monkeypatch.setenv("AUTODIAG_LISTEN_PORT", "9001")
    monkeypatch.setenv("AUTODIAG_OLLAMA_ADVISOR_MODEL", "some/model:tag")
    s = load_settings(env_file=None)
    assert s.listen_port == 9001
    assert s.ollama_advisor_model == "some/model:tag"


def test_toml_config_file_is_read_and_env_wins(monkeypatch, tmp_path: Path) -> None:
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        'listen_port = 9100\nollama_primary_url = "http://ollama.example.internal:11434"\n'
        'ollama_advisor_model = "from-toml"\n'
    )
    monkeypatch.setenv("AUTODIAG_CONFIG", str(cfg))
    monkeypatch.setenv("AUTODIAG_OLLAMA_ADVISOR_MODEL", "from-env")
    s = load_settings(env_file=None)
    assert s.listen_port == 9100
    assert s.ollama_primary_url == "http://ollama.example.internal:11434"
    assert s.ollama_advisor_model == "from-env"


def test_data_dir_expands_user(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AUTODIAG_CONFIG", str(tmp_path / "missing.toml"))
    monkeypatch.setenv("AUTODIAG_DATA_DIR", "~/autodiag-data")
    s = load_settings(env_file=None)
    assert "~" not in str(s.data_dir)
    assert s.data_dir.is_absolute()


def test_settings_is_pydantic_model() -> None:
    assert hasattr(Settings, "model_fields")
