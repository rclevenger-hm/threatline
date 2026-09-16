from __future__ import annotations

import os

from threatline.web import create_server


def main() -> None:
    host = os.getenv("THREATLINE_HOST", "127.0.0.1")
    port = int(os.getenv("THREATLINE_PORT", "8080"))
    server = create_server(host, port)
    address, bound_port = server.server_address[:2]
    print(f"Threatline listening on http://{address}:{bound_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
