from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "SahteMi"
    app_env: str = "development"
    app_version: str = "0.1.0"
    log_level: str = "INFO"

    database_url: str = "postgresql+asyncpg://sahtemi:sahtemi_dev@localhost:5432/sahtemi"

    llm_provider: str = "deepseek"
    llm_base_url: str = "https://api.deepseek.com/v1"
    llm_api_key: str = ""
    llm_model: str = "deepseek-chat"

    google_safe_browsing_api_key: str = ""
    telegram_bot_token: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()
