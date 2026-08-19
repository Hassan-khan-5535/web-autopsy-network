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

    # Extension 1: bounded assessment policy. Safe defaults are intentionally conservative.
    assessment_policy_version: str = "assessment-v1"
    assessment_encryption_key: str | None = None
    assessment_allow_private_targets: bool = False
    assessment_private_target_allowlist: str = ""
    assessment_robots_override_profiles: str = "aggressive"
    assessment_safe_max_depth: int = 2
    assessment_safe_max_requests: int = 30
    assessment_safe_max_concurrency: int = 2
    assessment_safe_min_rate_limit_ms: int = 1000
    assessment_normal_max_depth: int = 3
    assessment_normal_max_requests: int = 50
    assessment_normal_max_concurrency: int = 3
    assessment_normal_min_rate_limit_ms: int = 500
    assessment_aggressive_max_depth: int = 5
    assessment_aggressive_max_requests: int = 100
    assessment_aggressive_max_concurrency: int = 4
    assessment_aggressive_min_rate_limit_ms: int = 250

    # Extension 2: bounded passive and active-safe recon controls.
    recon_passive_timeout_seconds: float = 8.0
    recon_ct_max_records: int = 200
    recon_dns_record_types: str = "A,AAAA,CNAME,MX,NS,TXT"
    recon_active_safe_max_candidates: int = 24
    recon_active_safe_max_sitemap_urls: int = 10
    recon_active_safe_max_body_bytes: int = 1048576
    recon_active_safe_path_wordlist: str = "/.well-known/security.txt,/sitemap.xml,/sitemap_index.xml,/manifest.json,/openapi.json,/swagger.json,/api,/graphql,/login,/admin,/health,/status,/docs"

    queue_backend_url: str = "redis://localhost:6379/0"
    queue_mode: str = "auto"
    max_concurrent_scans: int = 5
    max_concurrent_tasks_per_pool: int = 2
    scan_timeout_seconds: int = 1800
    task_heartbeat_seconds: int = 15
    task_max_retries: int = 2
    task_retry_backoff_seconds: int = 2
    orchestration_task_timeout_seconds: int = 180
    orchestration_min_task_dispatch_budget: int = 32
    orchestration_dispatches_per_request: int = 16

    # Extension 16: verified local rule and signature package lifecycle.
    update_package_hmac_key: str = "development-local-update-key"
    update_package_cache_dir: str = ".web-autopsy-cache"
    update_package_scanner_version: str = "0.16.0"
    update_package_require_signature: bool = True

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
