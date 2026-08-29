"""Small stdlib-only vendor-neutral inventory fixture for local demos and tests.

The fixture returns synthetic records from a deliberately tiny HTTP contract. It
must stay on isolated demo networks and must never be pointed at customer systems.
"""

import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

SIMULATED_TOKEN = "simulated-asset-source-token"  # noqa: S105 - synthetic fixture credential
ASSET_COUNT = 24


def synthetic_assets() -> list[dict]:
    """Return the same 24 synthetic assets on every successful request."""
    assets = []
    for number in range(1, ASSET_COUNT + 1):
        is_server = number % 4 == 0
        assets.append(
            {
                "name": f"ASSET-SIM-{number:03d}",
                "ip": f"198.51.100.{number}",
                "mac": f"02:00:5e:10:{number // 256:02x}:{number % 256:02x}",
                "type": "Server" if is_server else "Workstation",
                "os": "Ubuntu 24.04" if is_server else "Windows 11",
                "segment": "Lab-Inventory",
                "edr_status": "Simulated Agent",
                "control_coverage": "full" if number % 3 else "partial",
                "network_exposure": "internal",
                "auth_method": "certificate" if is_server else "password",
                "criticality": "high" if is_server else "medium",
                "data_classification": "Internal",
                "software_stack": ["OpenSSH 9.6" if is_server else "Office Suite"],
                "cpe": [],
                "dependencies": [],
                "attrs": {"source_record_id": f"asset-record-{number:03d}"},
            }
        )
    return assets


class AssetSourceHandler(BaseHTTPRequestHandler):
    server_version = "KepryxAssetSourceMock/0.9"
    retry_attempts = 0
    rate_limit_attempts = 0

    def _send_json(self, status: int, payload: dict):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        return self.headers.get("X-API-Key") == SIMULATED_TOKEN

    def do_GET(self):  # noqa: N802 - stdlib handler API
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._send_json(200, {"status": "ok", "simulated": True})
            return
        if not self._authorized():
            self._send_json(401, {"error": "simulated authentication required"})
            return
        if parsed.path == "/v1/assets":
            self._send_json(200, {"source": "synthetic-asset-api", "assets": synthetic_assets()})
            return
        if parsed.path == "/v1/assets-retry":
            AssetSourceHandler.retry_attempts += 1
            if AssetSourceHandler.retry_attempts < 3:
                self._send_json(503, {"error": "temporary synthetic outage"})
                return
            self._send_json(200, {"source": "synthetic-asset-api", "assets": synthetic_assets()})
            return
        if parsed.path == "/v1/assets-rate-limit":
            AssetSourceHandler.rate_limit_attempts += 1
            if AssetSourceHandler.rate_limit_attempts < 3:
                self._send_json(429, {"error": "synthetic rate limit"})
                return
            self._send_json(200, {"source": "synthetic-asset-api", "assets": synthetic_assets()})
            return
        if parsed.path == "/v1/assets-timeout":
            time.sleep(0.25)
            self._send_json(200, {"source": "synthetic-asset-api", "assets": synthetic_assets()})
            return
        self._send_json(404, {"error": "not found"})

    def log_message(self, _format, *_args):
        # Keep demo output deterministic and free of request credentials.
        return


def create_server(host: str = "127.0.0.1", port: int = 8766) -> ThreadingHTTPServer:
    AssetSourceHandler.retry_attempts = 0
    AssetSourceHandler.rate_limit_attempts = 0
    return ThreadingHTTPServer((host, port), AssetSourceHandler)


def main() -> None:
    parser = argparse.ArgumentParser(description="Synthetic Asset Source API for Kepryx demos")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8766, type=int)
    args = parser.parse_args()
    server = create_server(args.host, args.port)
    print(f"Synthetic Asset Source API listening on http://{args.host}:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
