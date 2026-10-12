from eeap_shared.utils.settings import ServiceSettings


class AssetSettings(ServiceSettings):
    service_name: str = "asset-service"
    eeap_run_embedded_worker: bool = False


settings = AssetSettings()
SCHEMA = "asset"
