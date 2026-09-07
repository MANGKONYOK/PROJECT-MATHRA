"""
Project Mathra - Enterprise Configuration Loader
Loads environment variables using Pydantic Settings (Pydantic v2).
"""

from functools import lru_cache  # lru_cache is used to cache the settings instance
from pydantic_settings import BaseSettings, SettingsConfigDict  # BaseSettings is used to load environment variables
from pydantic import Field  # Field is used to define the fields of the settings

# Settings class is used to load environment variables
class Settings(BaseSettings):

    model_config = SettingsConfigDict(
        env_file=".env",                # .env is a file that contains environment variables
        env_file_encoding="utf-8",      # utf-8 is the encoding of the file
        extra="ignore",                 # extra="ignore" means that we ignore extra environment variables
        case_sensitive=False,           # case_sensitive=False means that we ignore the case of the environment variables
    )

    # Server Settings
    proxy_host: str = Field(default="0.0.0.0", alias="PROXY_HOST")       # 0.0.0.0 means that we listen on all available interfaces
    proxy_port: int = Field(default=8000, alias="PROXY_PORT")            # 8000 is the port that we listen on
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")            # INFO is the log level that we use
    environment: str = Field(default="development", alias="ENVIRONMENT") # development is the environment that we use

    # Database Configuration (SQLAlchemy Async Engine)
    # Default: sqlite+aiosqlite:///./backend/data/mathra_events.db
    # Production: postgresql+asyncpg://user:pass@host:5432/mathra
    database_url: str = Field(
        default="sqlite+aiosqlite:///./backend/data/mathra_events.db",  # Default: SQLite with aiosqlite
        alias="DATABASE_URL",  # Alias for DATABASE_URL
    )

    # Model Providers & Routing
    openai_api_key: str = Field(default="", alias="OPENAI_API_KEY")   
    ollama_base_url: str = Field(default="http://localhost:11434", alias="OLLAMA_BASE_URL")
    default_model: str = Field(default="gpt-4o-mini", alias="DEFAULT_MODEL")
    fallback_local_model: str = Field(default="ollama/llama3", alias="FALLBACK_LOCAL_MODEL")

    # Security & DLP Pipeline Flags
    enable_pii_redaction: bool = Field(default=True, alias="ENABLE_PII_REDACTION")
    enable_secret_scanning: bool = Field(default=True, alias="ENABLE_SECRET_SCANNING")
    enable_guardrails: bool = Field(default=True, alias="ENABLE_GUARDRAILS")
    simulation_mode: bool = Field(default=True, alias="SIMULATION_MODE")

    # Red Team Engine Configuration
    redteam_concurrency: int = Field(default=10, alias="REDTEAM_CONCURRENCY")
    redteam_target_url: str = Field(
        default="http://localhost:8000/v1/chat/completions",
        alias="REDTEAM_TARGET_URL",
    )

    # Overwatch Network Monitor Configuration
    overwatch_listen_port: int = Field(default=8080, alias="OVERWATCH_LISTEN_PORT")


@lru_cache()  # lru_cache is used to cache the settings instance
def get_settings() -> Settings:                # get_settings is used to get the settings instance
    """Cached singleton settings instance."""
    return Settings()                          # Returns the settings instance