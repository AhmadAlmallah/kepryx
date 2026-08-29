"""Shared network destination policy for outbound integrations."""

from ipaddress import IPv4Address, IPv6Address


def is_public_ip(address: IPv4Address | IPv6Address) -> bool:
    """Return whether an address is globally routable for outbound delivery.

    A global-only policy rejects private, loopback, link-local, multicast,
    documentation, unspecified, and shared-address ranges. This is stricter
    than checking only ``is_private`` and is appropriate for destinations that
    must not become an SSRF primitive.
    """

    return address.is_global
