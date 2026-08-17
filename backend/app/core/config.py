from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Web Autopsy Network API"
    app_env: str = "development"
    log_level: str = "INFO"
    api_v1_prefix: str = "/api/v1"
    database_url: str = "postgresql+psycopg://web_autopsy:change-me-for-local-development@localhost:5432/web_autopsy"
    cors_origins: str = "http://localhost:3000"
    browser_worker_url: str = "http://browser-worker:8001"
    jwt_secret: str = "replace-with-a-long-local-only-secret"


    crawl_default_max_depth: int = 2
    crawl_max_depth_cap: int = 5
    crawl_default_max_pages: int = 30
    crawl_max_pages_cap: int = 100
    crawl_default_concurrency: int = 2
    crawl_max_concurrency_cap: int = 4
    crawl_default_delay_ms: int = 1000
    crawl_min_delay_ms: int = 100
    crawl_same_domain_mode: str = "hostname"

    queue_backend_url: str = "redis://localhost:6379/0"
    queue_mode: str = "auto"
    max_concurrent_scans: int = 5
    max_concurrent_tasks_per_pool: int = 2
    scan_timeout_seconds: int = 1800
    task_heartbeat_seconds: int = 15
    task_max_retries: int = 2
    task_retry_backoff_seconds: int = 2

    llm_api_key: str | None = None
    llm_api_base: str | None = None
    llm_model: str = "gpt-4o-mini"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
