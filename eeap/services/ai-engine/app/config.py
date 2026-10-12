from typing import Literal

from eeap_shared.utils.settings import ServiceSettings


class AiSettings(ServiceSettings):
    service_name: str = "ai-engine"
    scoring_model_version: str = "v1"
    ai_llm_provider: Literal["none", "azure_openai", "openai", "ollama"] = "none"


settings = AiSettings()
SCHEMA = "ai"
