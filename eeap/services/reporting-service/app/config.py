from eeap_shared.utils.settings import ServiceSettings, read_secret_file


class ReportingSettings(ServiceSettings):
    service_name: str = "reporting-service"
    reports_bucket: str = "eeap-reports"
    report_url_ttl_seconds: int = 300
    report_retention_days: int = 180
    report_organization: str = "EEAP"
    report_max_findings: int = 1000
    upstream_timeout_seconds: float = 20.0

    ai_engine_url: str = "http://ai-engine:8000"
    assessment_service_url: str = "http://assessment-service:8000"

    minio_access_key: str | None = None
    minio_secret_key_file: str | None = None

    def minio_secret_key(self) -> str:
        return read_secret_file(self.minio_secret_key_file) or ""

    def upstream_urls(self) -> dict[str, str]:
        return {"ai": self.ai_engine_url, "assessment": self.assessment_service_url}


settings = ReportingSettings()
SCHEMA = "reporting"
