"""Deterministic, harmless HTTP target for the isolated Nmap demo network."""

from __future__ import annotations

import argparse
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


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Isolated synthetic discovery target")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(argv)
    server = ThreadingHTTPServer((args.host, args.port), TargetHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
