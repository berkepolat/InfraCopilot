from eeap_shared.utils.settings import ServiceSettings


class ReportingSettings(ServiceSettings):
    service_name: str = "reporting-service"
    reports_bucket: str = "eeap-reports"
    report_url_ttl_seconds: int = 300


settings = ReportingSettings()
SCHEMA = "reporting"
