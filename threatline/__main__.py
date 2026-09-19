from __future__ import annotations

import os

from threatline import __version__
from threatline.web import create_server


def main() -> None:
    host = os.getenv("THREATLINE_HOST", "127.0.0.1")
    port = int(os.getenv("THREATLINE_PORT", "8080"))
    server = create_server(host, port)
    address, bound_port = server.server_address[:2]
    diagnostics = server.RequestHandlerClass.registry.diagnostics()
    providers = ", ".join(item.name for item in diagnostics) or "none"
    degraded = [item.name for item in diagnostics if item.health.status.value == "unavailable"]
    provider_state = f"; unavailable: {', '.join(degraded)}" if degraded else ""
    print(f"Threatline {__version__} listening on http://{address}:{bound_port}")
    print(f"Providers: {providers}{provider_state}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
