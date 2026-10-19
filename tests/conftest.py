import pytest

from app.config import get_settings


@pytest.fixture(autouse=True)
def isolated_test_database(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "app_env", "development")
    monkeypatch.setattr(settings, "demo_login_enabled", False)
    monkeypatch.setattr(
        settings,
        "database_url",
        f"sqlite+aiosqlite:///{tmp_path / 'aegisauth-test.db'}",
    )
