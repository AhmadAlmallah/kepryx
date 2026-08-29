"""Executable scanner parsing and process-boundary tests."""

import asyncio

import pytest

from app.core import scan_authorization
from app.services.scanner import NetworkScanner, ScanExecutionError

NMAP_XML = """
<nmaprun>
  <host endtime="20260828010101">
    <status state="up"/>
    <address addr="198.51.100.10" addrtype="ipv4"/>
    <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Example"/>
    <hostnames><hostname name="lab-node"/></hostnames>
    <os><osmatch name="Linux 6.x"/></os>
    <ports>
      <port protocol="tcp" portid="443"><state state="open"/>
        <service name="https" product="nginx" version="1.25">
          <cpe>cpe:2.3:a:nginx:nginx:1.25:*:*:*:*:*:*:*</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="22"><state state="closed"/></port>
    </ports>
  </host>
  <host><status state="down"/><address addr="198.51.100.11" addrtype="ipv4"/></host>
</nmaprun>
"""


def test_parse_xml_keeps_up_hosts_and_open_service_evidence():
    hosts = NetworkScanner()._parse_xml(NMAP_XML)

    assert len(hosts) == 1
    assert hosts[0].ip == "198.51.100.10"
    assert hosts[0].mac_vendor == "Example"
    assert hosts[0].hostname == "lab-node"
    assert hosts[0].os_guess == "Linux 6.x"
    assert hosts[0].services == [
        {
            "port": 443,
            "protocol": "tcp",
            "service": "https",
            "product": "nginx",
            "version": "1.25",
            "cpe": ["cpe:2.3:a:nginx:nginx:1.25:*:*:*:*:*:*:*"],
        }
    ]


def test_parse_xml_rejects_invalid_or_incomplete_output():
    with pytest.raises(ScanExecutionError, match="invalid XML"):
        NetworkScanner()._parse_xml("<nmaprun>")
    assert NetworkScanner()._parse_xml("<nmaprun><host><status state='up'/></host></nmaprun>") == []


@pytest.mark.asyncio
async def test_discover_and_service_scan_apply_authorization(monkeypatch):
    captured = []

    async def fake_run(args):
        captured.append(args)
        return []

    scanner = NetworkScanner()
    monkeypatch.setattr(scanner, "_run", fake_run)
    monkeypatch.setattr(scan_authorization.settings, "SCAN_NETWORKS", ["198.51.100.0/24"])
    await scanner.discover("198.51.100.0/28", ["198.51.100.15"])
    await scanner.service_scan("198.51.100.10")

    assert "198.51.100.0/28" in captured[0]
    assert "--exclude" in captured[0]
    assert captured[1][-1] == "198.51.100.10"
    monkeypatch.setattr(scan_authorization.settings, "SCAN_NETWORKS", [])
    with pytest.raises(scan_authorization.ScanAuthorizationError):
        await scanner.service_scan("203.0.113.10")


class _Process:
    def __init__(self, stdout=b"<nmaprun/>", stderr=b"", returncode=0, error=None):
        self.stdout = asyncio.StreamReader()
        self.stderr = asyncio.StreamReader()
        self.stdout.feed_data(stdout)
        self.stdout.feed_eof()
        self.stderr.feed_data(stderr)
        self.stderr.feed_eof()
        self.returncode = returncode
        self.error = error

    async def communicate(self):
        if self.error:
            raise self.error
        return await self.stdout.read(), await self.stderr.read()


class _RunningProcess(_Process):
    def __init__(self):
        super().__init__(returncode=None)
        self.killed = False
        self.waited = False

    def kill(self):
        self.killed = True
        self.returncode = -9

    async def wait(self):
        self.waited = True


@pytest.mark.asyncio
async def test_run_reports_nonzero_missing_binary_and_timeout(monkeypatch):
    scanner = NetworkScanner()

    async def nonzero_process(*_args, **_kwargs):
        return _Process(stderr=b"permission denied", returncode=2)

    monkeypatch.setattr("app.services.scanner.asyncio.create_subprocess_exec", nonzero_process)
    with pytest.raises(ScanExecutionError, match="permission denied"):
        await scanner._run(["nmap"])

    async def missing_process(*_args, **_kwargs):
        raise FileNotFoundError

    monkeypatch.setattr("app.services.scanner.asyncio.create_subprocess_exec", missing_process)
    with pytest.raises(ScanExecutionError, match="not found"):
        await scanner._run(["nmap"])

    async def timeout(awaitable, timeout):
        del timeout
        awaitable.close()
        raise TimeoutError

    async def successful_process(*_args, **_kwargs):
        return _Process()

    monkeypatch.setattr("app.services.scanner.asyncio.create_subprocess_exec", successful_process)
    monkeypatch.setattr("app.services.scanner.asyncio.wait_for", timeout)
    with pytest.raises(ScanExecutionError, match="timed out"):
        await scanner._run(["nmap"])


@pytest.mark.asyncio
async def test_run_kills_and_reaps_process_after_timeout(monkeypatch):
    process = _RunningProcess()

    async def running_process(*_args, **_kwargs):
        return process

    async def timeout(awaitable, timeout):
        del timeout
        awaitable.close()
        raise TimeoutError

    monkeypatch.setattr("app.services.scanner.asyncio.create_subprocess_exec", running_process)
    monkeypatch.setattr("app.services.scanner.asyncio.wait_for", timeout)

    with pytest.raises(ScanExecutionError, match="timed out"):
        await NetworkScanner()._run(["nmap"])

    assert process.killed
    assert process.waited
