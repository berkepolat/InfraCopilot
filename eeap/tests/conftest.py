import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GATEWAY_DIR = ROOT / "services" / "api-gateway"

# Gateway modules are imported as the top-level `app` package, as inside the container.
sys.path.insert(0, str(GATEWAY_DIR))


def load_service_module(service: str, module: str, alias: str):
    """Loads a dependency-free module of another service (every service package is named `app`)."""
    spec = importlib.util.spec_from_file_location(alias, ROOT / "services" / service / "app" / f"{module}.py")
    loaded = importlib.util.module_from_spec(spec)
    sys.modules[alias] = loaded
    spec.loader.exec_module(loaded)
    return loaded


def load_service_package(service: str, alias: str):
    """Loads a service's `app` package under `alias` so modules with relative imports can be imported."""
    if alias in sys.modules:
        return sys.modules[alias]
    init = ROOT / "services" / service / "app" / "__init__.py"
    spec = importlib.util.spec_from_file_location(alias, init, submodule_search_locations=[str(init.parent)])
    package = importlib.util.module_from_spec(spec)
    sys.modules[alias] = package
    spec.loader.exec_module(package)
    return package
