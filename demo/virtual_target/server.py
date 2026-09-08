"""Deterministic, harmless HTTP target for the isolated Nmap demo network."""

from __future__ import annotations

import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class TargetHandler(BaseHTTPRequestHandler):
    server_version = "KepryxDemoTarget/0.9"

    def do_GET(self):  # noqa: N802 - stdlib handler API
        name = os.environ.get("DEMO_TARGET_NAME", "virtual-target")
        body = (
            f"Kepryx local demo target: {name}\n"
            "Synthetic TEST-NET-2 service for an authorized discovery demonstration.\n"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Demo-Synthetic", "true")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", 8080), TargetHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
