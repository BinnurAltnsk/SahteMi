"""Telegram botu için ortam değişkeni ayarları."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class BotSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    telegram_bot_token: str = ""
    api_base_url: str = "http://localhost:8000"
    api_timeout_seconds: float = 15.0
    log_level: str = "INFO"


@lru_cache
def get_bot_settings() -> BotSettings:
    return BotSettings()
