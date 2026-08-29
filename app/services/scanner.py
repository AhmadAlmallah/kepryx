"""Network scanner — nmap wrapper for host discovery and service enumeration."""

import asyncio
import logging
from dataclasses import dataclass

from defusedxml import ElementTree

from app.core.config import settings
from app.core.scan_authorization import authorize_scan_host, authorize_scan_network

logger = logging.getLogger(__name__)


class ScanExecutionError(RuntimeError):
    """Raised when nmap cannot produce trustworthy XML output."""


@dataclass
class DiscoveredHost:
    ip: str
    mac: str | None
    mac_vendor: str | None
    hostname: str | None
    os_guess: str | None
    state: str
    services: list[dict]
    last_seen: str


class NetworkScanner:
    """Wraps nmap. Workers run in containers with NET_RAW/NET_ADMIN."""

    async def discover(
        self, cidr: str, excluded_ips: list[str] | None = None
    ) -> list[DiscoveredHost]:
        """Layer 2/3 host discovery — fast sweep, no port scan."""
        cidr = authorize_scan_network(cidr)
        args = [
            "nmap",
            "-sn",
            "-PR",
            "-PE",
            "-PA21,22,23,80,443,3389",
            f"-T{settings.NMAP_TIMING}",
            "-oX",
            "-",
        ]
        if excluded_ips:
            args.extend(["--exclude", ",".join(excluded_ips)])
        args.append(cidr)
        return await self._run(args)

    async def service_scan(self, target: str) -> list[DiscoveredHost]:
        """Unprivileged service fingerprinting on a single authorized host.

        OS fingerprinting (nmap ``-O``) requires root and is intentionally not
        enabled in the least-privilege worker. Service/version evidence remains
        available through ``-sV``.
        """
        target = authorize_scan_host(target)
        args = [
            "nmap",
            "-sV",
            "-p",
            "22,80,135,139,443,445,3389,5985,8080,8443",
            f"-T{settings.NMAP_TIMING}",
            "-oX",
            "-",
            target,
        ]
        return await self._run(args)

    async def _run(self, args: list[str]) -> list[DiscoveredHost]:
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=settings.SCAN_TIMEOUT_SEC
            )
            if proc.returncode != 0:
                detail = stderr.decode(errors="replace")[:500]
                logger.error("nmap failed: %s", detail)
                raise ScanExecutionError(detail or "nmap exited unsuccessfully")
            return self._parse_xml(stdout.decode())
        except TimeoutError:
            logger.error(f"nmap timeout for {args}")
            raise ScanExecutionError("nmap execution timed out") from None
        except FileNotFoundError:
            logger.error("nmap binary not found — install in worker container")
            raise ScanExecutionError("nmap binary not found") from None

    def _parse_xml(self, xml: str) -> list[DiscoveredHost]:
        hosts = []
        try:
            root = ElementTree.fromstring(xml)
        except ElementTree.ParseError as e:
            logger.error(f"nmap XML parse failed: {e}")
            raise ScanExecutionError("nmap returned invalid XML") from e

        for host in root.findall("host"):
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue

            ip = None
            mac = None
            mac_vendor = None
            for addr in host.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip = addr.get("addr")
                elif addr.get("addrtype") == "mac":
                    mac = addr.get("addr")
                    mac_vendor = addr.get("vendor")
            if not ip:
                continue

            hostname = None
            hostnames = host.find("hostnames")
            if hostnames is not None:
                hn = hostnames.find("hostname")
                if hn is not None:
                    hostname = hn.get("name")

            os_guess = None
            os_elem = host.find("os")
            if os_elem is not None:
                match = os_elem.find("osmatch")
                if match is not None:
                    os_guess = match.get("name")

            services = []
            ports = host.find("ports")
            if ports is not None:
                for port in ports.findall("port"):
                    state = port.find("state")
                    if state is not None and state.get("state") == "open":
                        svc = port.find("service")
                        services.append(
                            {
                                "port": int(port.get("portid", 0)),
                                "protocol": port.get("protocol"),
                                "service": svc.get("name") if svc is not None else None,
                                "product": svc.get("product") if svc is not None else None,
                                "version": svc.get("version") if svc is not None else None,
                                "cpe": [c.text for c in svc.findall("cpe")]
                                if svc is not None
                                else [],
                            }
                        )

            hosts.append(
                DiscoveredHost(
                    ip=ip,
                    mac=mac,
                    mac_vendor=mac_vendor,
                    hostname=hostname,
                    os_guess=os_guess,
                    state="up",
                    services=services,
                    last_seen=host.get("endtime", ""),
                )
            )
        return hosts
