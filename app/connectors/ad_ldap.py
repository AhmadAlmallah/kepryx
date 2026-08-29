"""Active Directory / LDAP connector — pulls domain-joined endpoints."""

import logging
import ssl

from ldap3 import ALL, SUBTREE, Connection, Server, Tls

from app.connectors import BaseConnector, register_connector

logger = logging.getLogger(__name__)


def _tls_config(config: dict) -> Tls:
    """Build an explicitly validating LDAPS configuration.

    ldap3's implicit default TLS object does not validate the server
    certificate. Use the system trust store by default, or an operator-
    supplied CA bundle for private enterprise PKI.
    """
    ca_certs_file = config.get("ca_certs_file")
    if ca_certs_file is not None and (not isinstance(ca_certs_file, str) or not ca_certs_file):
        raise ValueError("ca_certs_file must be a non-empty path when supplied")
    return Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ca_certs_file)


@register_connector("ad_ldap")
class ADLDAPConnector(BaseConnector):
    """
    Config:
      server: ldaps://dc.example.local:636
      ca_certs_file: /run/secrets/ad-ca.pem (optional; system trust store otherwise)
      base_dn: DC=example,DC=local
      bind_dn: CN=svc-kepryx,OU=Service Accounts,DC=example,DC=local
      bind_password: <encrypted by the integration service>
      filter: (objectClass=computer)
    """

    async def fetch_inventory(self) -> list[dict]:
        server = Server(
            self.config["server"],
            get_info=ALL,
            use_ssl=True,
            tls=_tls_config(self.config),
        )
        conn = Connection(
            server,
            user=self.config["bind_dn"],
            password=self.config["bind_password"],
            auto_bind=True,
        )

        conn.search(
            search_base=self.config["base_dn"],
            search_filter=self.config.get("filter", "(objectClass=computer)"),
            search_scope=SUBTREE,
            attributes=[
                "cn",
                "dNSHostName",
                "operatingSystem",
                "operatingSystemVersion",
                "lastLogonTimestamp",
                "userAccountControl",
                "distinguishedName",
            ],
        )

        assets = []
        for entry in conn.entries:
            name = str(entry.cn) if entry.cn else None
            if not name:
                continue
            os_name = str(entry.operatingSystem) if entry.operatingSystem else None
            os_ver = str(entry.operatingSystemVersion) if entry.operatingSystemVersion else ""
            assets.append(
                {
                    "name": name,
                    "hostname": str(entry.dNSHostName) if entry.dNSHostName else name,
                    "type": self._classify(os_name),
                    "os": f"{os_name} {os_ver}".strip() if os_name else None,
                    "segment": "Corporate",
                    "auth_method": "mfa"
                    if "DomainController" in str(entry.distinguishedName)
                    else "password",
                    "criticality": "tier-1" if "Domain Controller" in (os_name or "") else "medium",
                    "attrs": {"dn": str(entry.distinguishedName)},
                }
            )
        conn.unbind()
        return assets

    def _classify(self, os_name: str | None) -> str:
        if not os_name:
            return "Endpoint"
        os_lower = os_name.lower()
        if "server" in os_lower:
            return "Server"
        if "windows" in os_lower:
            return "Endpoint"
        return "Endpoint"

    async def test_connection(self) -> bool:
        try:
            server = Server(
                self.config["server"],
                use_ssl=True,
                tls=_tls_config(self.config),
            )
            conn = Connection(
                server,
                user=self.config["bind_dn"],
                password=self.config["bind_password"],
                auto_bind=True,
            )
            conn.unbind()
            return True
        except Exception as e:
            logger.error(f"AD test failed: {e}")
            return False
