"""Fail-closed authorization helpers for active network scanning."""

from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network

from app.core.config import settings


class ScanAuthorizationError(ValueError):
    """Raised when a target is invalid or outside the approved scan boundary."""


def normalize_scan_network(cidr: str) -> str:
    """Validate and canonicalize a CIDR without applying authorization policy."""
    try:
        return str(ip_network(cidr, strict=False))
    except ValueError as exc:
        raise ScanAuthorizationError("invalid scan CIDR") from exc


def authorize_scan_network(
    cidr: str,
    *,
    allowed_cidrs: list[str] | None = None,
    max_hosts: int | None = None,
) -> str:
    """Return a canonical CIDR only when it is contained in an approved range."""
    target = ip_network(normalize_scan_network(cidr), strict=True)
    allowed_values = settings.SCAN_NETWORKS if allowed_cidrs is None else allowed_cidrs
    host_limit = settings.MAX_SCAN_HOSTS if max_hosts is None else max_hosts

    if target.num_addresses > host_limit:
        raise ScanAuthorizationError(
            f"scan target contains {target.num_addresses} addresses; limit is {host_limit}"
        )
    if not allowed_values:
        raise ScanAuthorizationError("network scanning is disabled; SCAN_NETWORKS is empty")

    for value in allowed_values:
        try:
            allowed = ip_network(value, strict=False)
        except ValueError as exc:
            raise ScanAuthorizationError("SCAN_NETWORKS contains an invalid CIDR") from exc
        if isinstance(target, IPv4Network) and isinstance(allowed, IPv4Network):
            is_authorized = target.subnet_of(allowed)
        elif isinstance(target, IPv6Network) and isinstance(allowed, IPv6Network):
            is_authorized = target.subnet_of(allowed)
        else:
            is_authorized = False
        if is_authorized:
            return str(target)

    raise ScanAuthorizationError("scan target is outside the authorized SCAN_NETWORKS boundary")


def authorize_scan_host(target: str, *, allowed_cidrs: list[str] | None = None) -> str:
    """Return a canonical host address only when it belongs to an approved range."""
    try:
        host = ip_address(target)
    except ValueError as exc:
        raise ScanAuthorizationError("service scan target must be a single IP address") from exc

    allowed_values = settings.SCAN_NETWORKS if allowed_cidrs is None else allowed_cidrs
    if not allowed_values:
        raise ScanAuthorizationError("network scanning is disabled; SCAN_NETWORKS is empty")

    for value in allowed_values:
        try:
            allowed = ip_network(value, strict=False)
        except ValueError as exc:
            raise ScanAuthorizationError("SCAN_NETWORKS contains an invalid CIDR") from exc
        if host.version == allowed.version and host in allowed:
            return str(host)

    raise ScanAuthorizationError("service scan target is outside SCAN_NETWORKS")
