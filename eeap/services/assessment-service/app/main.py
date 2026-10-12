from eeap_shared.utils.service import build_service_app

from .api import router
from .config import SCHEMA, settings
from .storage import ObjectStore

app = build_service_app(settings, title="EEAP Assessment Service", routers=[router], outbox_schema=SCHEMA)
app.state.object_store = ObjectStore(settings)
