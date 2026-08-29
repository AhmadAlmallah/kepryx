"""Active Directory / LDAP connector — pulls domain-joined endpoints."""

import logging

from ldap3 import ALL, SUBTREE, Connection, Server

from app.connectors import BaseConnector, register_connector

logger = logging.getLogger(__name__)


@register_connector("ad_ldap")
class ADLDAPConnector(BaseConnector):
    """
    Config:
      server: ldaps://dc.example.local:636
      base_dn: DC=example,DC=local
      bind_dn: CN=svc-kepryx,OU=Service Accounts,DC=example,DC=local
      bind_password: <encrypted by the integration service>
      filter: (objectClass=computer)
    """

    async def fetch_inventory(self) -> list[dict]:
        server = Server(self.config["server"], get_info=ALL, use_ssl=True)
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
            server = Server(self.config["server"], use_ssl=True)
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
