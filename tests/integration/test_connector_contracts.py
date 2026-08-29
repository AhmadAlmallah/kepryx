"""Provider adapter contract tests using deterministic HTTP/SDK doubles."""

import pytest

from app.connectors.cloud_aws import AWSConnector
from app.connectors.dhcp_dns import DHCPDNSConnector
from app.connectors.edr_crowdstrike import CrowdStrikeConnector
from app.connectors.vuln_nessus import NessusConnector


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.text = "ok"

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeHttpClient:
    responses = {}

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def get(self, url, **_kwargs):
        return self.responses.get(("GET", url), FakeResponse({}, 404))

    async def post(self, url, **_kwargs):
        return self.responses.get(("POST", url), FakeResponse({}, 404))


@pytest.mark.asyncio
async def test_dhcp_connector_normalizes_infoblox_and_kea_leases(monkeypatch):
    monkeypatch.setattr("app.connectors.dhcp_dns.httpx.AsyncClient", FakeHttpClient)
    FakeHttpClient.responses = {
        ("GET", "https://dhcp.example/lease"): FakeResponse(
            [
                {
                    "binding_state": "ACTIVE",
                    "address": "198.51.100.10",
                    "client_hostname": "node-1",
                    "hardware": "00:11",
                },
                {"binding_state": "FREE", "address": "198.51.100.11"},
            ]
        ),
        ("GET", "https://dhcp.example/network"): FakeResponse({}, 200),
        ("POST", "https://kea.example"): FakeResponse(
            [
                {
                    "arguments": {
                        "leases": [
                            {
                                "ip-address": "198.51.100.12",
                                "hw-address": "00:22",
                                "hostname": "node-2",
                                "state": 0,
                            }
                        ]
                    }
                }
            ]
        ),
    }
    infoblox = DHCPDNSConnector(
        {
            "provider": "infoblox",
            "base_url": "https://dhcp.example",
            "username": "u",
            "password": "p",
        }
    )
    assets = await infoblox.fetch_inventory()
    assert assets[0]["name"] == "node-1"
    assert await infoblox.test_connection() is True
    kea = DHCPDNSConnector({"provider": "kea", "base_url": "https://kea.example"})
    assert (await kea.fetch_inventory())[0]["ip"] == "198.51.100.12"
    assert (
        await DHCPDNSConnector(
            {"provider": "unknown", "base_url": "https://x.example"}
        ).fetch_inventory()
        == []
    )


@pytest.mark.asyncio
async def test_nessus_connector_deduplicates_hosts_across_completed_scans(monkeypatch):
    monkeypatch.setattr("app.connectors.vuln_nessus.httpx.AsyncClient", FakeHttpClient)
    base = "https://nessus.example"
    FakeHttpClient.responses = {
        ("GET", f"{base}/scans"): FakeResponse(
            {
                "scans": [
                    {"id": 1, "status": "completed"},
                    {"id": 2, "status": "running"},
                    {"id": 3, "status": "completed"},
                ]
            }
        ),
        ("GET", f"{base}/scans/1"): FakeResponse(
            {
                "hosts": [
                    {
                        "host-ip": "198.51.100.20",
                        "hostname": "web-1",
                        "operating-system": "Linux",
                        "critical": 1,
                    }
                ]
            }
        ),
        ("GET", f"{base}/scans/3"): FakeResponse(
            {
                "hosts": [
                    {"host-ip": "198.51.100.20", "hostname": "web-1"},
                    {"host-ip": "198.51.100.21"},
                ]
            }
        ),
        ("GET", f"{base}/server/status"): FakeResponse({}, 200),
    }
    connector = NessusConnector({"base_url": base, "access_key": "a", "secret_key": "s"})
    assets = await connector.fetch_inventory()
    assert [asset["ip"] for asset in assets] == ["198.51.100.20", "198.51.100.21"]
    assert assets[0]["attrs"]["scan_ids"] == [1, 3]
    assert await connector.test_connection() is True


@pytest.mark.asyncio
async def test_crowdstrike_connector_batches_device_ids_and_filters_unnamed(monkeypatch):
    monkeypatch.setattr("app.connectors.edr_crowdstrike.httpx.AsyncClient", FakeHttpClient)
    base = "https://edr.example"
    FakeHttpClient.responses = {
        ("POST", f"{base}/oauth2/token"): FakeResponse({"access_token": "access"}),
        ("GET", f"{base}/devices/queries/devices/v1"): FakeResponse({"resources": ["d1", "d2"]}),
        ("GET", f"{base}/devices/entities/devices/v2"): FakeResponse(
            {
                "resources": [
                    {
                        "hostname": "endpoint-1",
                        "local_ip": "198.51.100.30",
                        "product_type_desc": "Workstation",
                        "agent_version": "7",
                    },
                    {"local_ip": "198.51.100.31"},
                ]
            }
        ),
    }
    connector = CrowdStrikeConnector(
        {"base_url": base, "client_id": "id", "client_secret": "secret"}
    )
    assets = await connector.fetch_inventory()
    assert len(assets) == 1
    assert assets[0]["name"] == "endpoint-1"
    assert assets[0]["control_coverage"] == "full"
    assert await connector.test_connection() is True


class _Paginator:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self):
        return self.pages


class _AWSClient:
    def __init__(self, service):
        self.service = service

    def get_paginator(self, name):
        if name == "describe_instances":
            return _Paginator(
                [
                    {
                        "Reservations": [
                            {
                                "Instances": [
                                    {
                                        "InstanceId": "i-1",
                                        "State": {"Name": "running"},
                                        "PrivateIpAddress": "198.51.100.40",
                                        "PublicIpAddress": "198.51.100.41",
                                        "Tags": [{"Key": "Name", "Value": "web"}],
                                        "SecurityGroups": [{"GroupId": "sg-1"}],
                                    }
                                ]
                            }
                        ]
                    }
                ]
            )
        return _Paginator(
            [
                {
                    "DBInstances": [
                        {
                            "DBInstanceIdentifier": "db-1",
                            "Engine": "postgres",
                            "EngineVersion": "16",
                            "PubliclyAccessible": False,
                            "StorageEncrypted": True,
                        }
                    ]
                }
            ]
        )


class _AWSSession:
    def client(self, service):
        return _AWSClient(service)


def test_aws_connector_maps_ec2_and_rds_without_network(monkeypatch):
    connector = AWSConnector({"regions": ["us-east-1"]})
    monkeypatch.setattr(connector, "_session", lambda _region: _AWSSession())
    assets = connector._fetch_sync()
    assert [asset["name"] for asset in assets] == ["web", "db-1"]
    assert assets[0]["network_exposure"] == "internet-facing"
    assert assets[1]["data_classification"] == "Confidential"
