from eeap_shared.utils.settings import ServiceSettings


class RelationshipSettings(ServiceSettings):
    service_name: str = "relationship-engine"
    graph_max_path_depth: int = 6
    graph_max_response_nodes: int = 2000
    graph_analysis_debounce_seconds: int = 60


settings = RelationshipSettings()
SCHEMA = "graph"
