from __future__ import annotations

from eeap_shared.utils.db import create_engine
from eeap_shared.utils.runtime import Subscription
from eeap_shared.utils.settings import ServiceSettings

from .discovery import DISCOVERY_GROUP, discovery_handler


def subscriptions(settings: ServiceSettings) -> list[Subscription]:
    engine = create_engine(settings, pool_size=5)
    return [Subscription(DISCOVERY_GROUP, ["eeap.discovery"], discovery_handler(engine))]
