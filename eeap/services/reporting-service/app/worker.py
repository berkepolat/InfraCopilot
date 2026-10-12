from __future__ import annotations

from eeap_shared.utils.events import log_only_handler
from eeap_shared.utils.runtime import Subscription
from eeap_shared.utils.settings import ServiceSettings


def subscriptions(_: ServiceSettings) -> list[Subscription]:
    # Rendering (Jinja2 -> HTML -> PDF) is implemented with the report templates (Phase 2+).
    return [Subscription("reporting-service.render", ["eeap.report"], log_only_handler("reporting-service.render"))]
