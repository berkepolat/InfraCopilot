from eeap_shared.utils.service import build_service_app

from .api import router
from .config import SCHEMA, settings

app = build_service_app(settings, title="EEAP Reporting Service", routers=[router], outbox_schema=SCHEMA)
