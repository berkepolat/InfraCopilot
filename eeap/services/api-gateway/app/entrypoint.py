from pathlib import Path

from eeap_shared.utils.runtime import ServiceRuntime, main

from .config import settings

if __name__ == "__main__":
    main(ServiceRuntime(
        settings=settings,
        asgi_app="app.main:app",
        versions_dir=Path(__file__).resolve().parent.parent / "migrations" / "versions",
        version_table_schema="iam",
    ))
