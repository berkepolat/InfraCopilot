from dataclasses import dataclass

from eeap_shared.utils.settings import ServiceSettings, read_secret_file


@dataclass(frozen=True)
class AdTarget:
    ldap_url: str
    base_dn: str | None
    bind_user: str
    bind_password: str
    ca_file: str | None
    timeout_seconds: int
    max_objects: int


WINRM_AUTH_METHODS = ("kerberos", "negotiate", "ntlm")


@dataclass(frozen=True)
class WinrmTarget:
    username: str
    password: str
    auth: str
    port: int
    use_tls: bool
    ca_file: str | None
    configuration_name: str
    timeout_seconds: int
    realm: str | None
    kdc: str | None


class AssessmentSettings(ServiceSettings):
    service_name: str = "assessment-service"
    evidence_bucket: str = "eeap-evidence"
    imports_bucket: str = "eeap-imports"
    minio_access_key: str | None = None
    minio_secret_key_file: str | None = None
    import_max_bytes: int = 50 * 1024 * 1024
    import_max_rows: int = 20_000
    risk_acceptance_max_days: int = 365

    ad_ldap_url: str | None = None
    ad_base_dn: str | None = None
    ad_bind_user: str | None = None
    ad_bind_password_file: str | None = None
    ad_tls_ca_file: str | None = None
    ad_timeout_seconds: int = 30
    ad_max_objects: int = 200_000

    # Comma-separated CIDRs that server-side network probes may target (required for NET runs).
    scan_allowed_cidrs: str | None = None
    net_probe_timeout_seconds: float = 3.0
    net_port_connect_timeout_seconds: float = 1.0
    net_port_scan_concurrency: int = 100

    # Credentialed Windows posture over WinRM through the EEAP.Posture JEA endpoint (docs/architecture/17).
    winrm_username: str | None = None
    winrm_password_file: str | None = None
    winrm_auth: str = "kerberos"
    winrm_port: int = 5986
    winrm_use_tls: bool = True
    winrm_ca_file: str | None = None
    winrm_configuration_name: str = "EEAP.Posture"
    winrm_timeout_seconds: int = 30
    winrm_concurrency: int = 8
    winrm_realm: str | None = None
    winrm_kdc: str | None = None
    # Comma-separated names (wildcards allowed) or SIDs expected in local Administrators (WIN-007).
    win_local_admins_allowed: str = ""

    def minio_secret_key(self) -> str:
        return read_secret_file(self.minio_secret_key_file) or ""

    def ad_target(self) -> AdTarget | None:
        """The configured AD domain, or None when the AD module is not configured."""
        password = read_secret_file(self.ad_bind_password_file) if self.ad_bind_password_file else None
        if not (self.ad_ldap_url and self.ad_bind_user and password):
            return None
        return AdTarget(ldap_url=self.ad_ldap_url, base_dn=self.ad_base_dn or None, bind_user=self.ad_bind_user,
                        bind_password=password, ca_file=self.ad_tls_ca_file or None,
                        timeout_seconds=self.ad_timeout_seconds, max_objects=self.ad_max_objects)

    def winrm_configured(self) -> bool:
        """Whether credentialed Windows collection is set up (the password is only mounted on workers)."""
        return bool(self.winrm_username)

    def winrm_target(self) -> WinrmTarget | None:
        password = read_secret_file(self.winrm_password_file) if self.winrm_password_file else None
        if not (self.winrm_username and password):
            return None
        auth = self.winrm_auth.lower()
        if auth not in WINRM_AUTH_METHODS:
            raise ValueError(f"WINRM_AUTH must be one of {', '.join(WINRM_AUTH_METHODS)}")
        return WinrmTarget(username=self.winrm_username, password=password, auth=auth, port=self.winrm_port,
                           use_tls=self.winrm_use_tls, ca_file=self.winrm_ca_file or None,
                           configuration_name=self.winrm_configuration_name,
                           timeout_seconds=self.winrm_timeout_seconds, realm=self.winrm_realm or None,
                           kdc=self.winrm_kdc or None)

    def local_admins_allowed(self) -> list[str]:
        return [p.strip() for p in self.win_local_admins_allowed.split(",") if p.strip()]


settings = AssessmentSettings()
SCHEMA = "assessment"
