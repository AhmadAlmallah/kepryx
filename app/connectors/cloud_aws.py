"""AWS cloud asset connector — EC2, RDS, Lambda via AWS Config + boto3."""

import asyncio
import logging

import boto3
from botocore.exceptions import ClientError

from app.connectors import BaseConnector, register_connector

logger = logging.getLogger(__name__)


@register_connector("cloud_aws")
class AWSConnector(BaseConnector):
    """
    Config:
      access_key_id: <optional encrypted static credential>
      secret_access_key: <optional encrypted static credential>
      regions: ["us-east-1", "eu-west-1"]
      use_assume_role: false
      role_arn: arn:aws:iam::xxx:role/KepryxReadOnly
    """

    def _session(self, region: str):
        kwargs = {"region_name": region}
        if self.config.get("access_key_id"):
            kwargs.update(
                aws_access_key_id=self.config["access_key_id"],
                aws_secret_access_key=self.config["secret_access_key"],
            )
        session = boto3.Session(**kwargs)
        role_arn = self.config.get("role_arn")
        if not role_arn:
            return session
        credentials = session.client("sts").assume_role(
            RoleArn=role_arn,
            RoleSessionName="kepryx-inventory",
            DurationSeconds=3600,
        )["Credentials"]
        return boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=region,
        )

    async def fetch_inventory(self) -> list[dict]:
        return await asyncio.to_thread(self._fetch_sync)

    def _fetch_sync(self) -> list[dict]:
        assets = []
        for region in self.config.get("regions", ["us-east-1"]):
            session = self._session(region)
            try:
                assets.extend(self._fetch_ec2(session, region))
                assets.extend(self._fetch_rds(session, region))
            except ClientError as e:
                logger.error(f"AWS {region} fetch failed: {e}")
        return assets

    def _fetch_ec2(self, session, region: str) -> list[dict]:
        ec2 = session.client("ec2")
        out = []
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for res in page.get("Reservations", []):
                for inst in res.get("Instances", []):
                    if inst.get("State", {}).get("Name") == "terminated":
                        continue
                    tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                    out.append(
                        {
                            "name": tags.get("Name", inst["InstanceId"]),
                            "ip": inst.get("PrivateIpAddress"),
                            "type": "Cloud Instance",
                            "os": inst.get("PlatformDetails", "Unknown"),
                            "segment": f"Cloud-AWS-{region}",
                            "network_exposure": "internet-facing"
                            if inst.get("PublicIpAddress")
                            else "cloud",
                            "auth_method": "certificate",
                            "criticality": tags.get("Criticality", "medium"),
                            "data_classification": tags.get("DataClass", "Internal"),
                            "attrs": {
                                "instance_id": inst["InstanceId"],
                                "instance_type": inst.get("InstanceType"),
                                "vpc_id": inst.get("VpcId"),
                                "public_ip": inst.get("PublicIpAddress"),
                                "subnet_id": inst.get("SubnetId"),
                                "security_groups": [
                                    sg["GroupId"] for sg in inst.get("SecurityGroups", [])
                                ],
                                "tags": tags,
                            },
                        }
                    )
        return out

    def _fetch_rds(self, session, region: str) -> list[dict]:
        rds = session.client("rds")
        out = []
        try:
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page.get("DBInstances", []):
                    out.append(
                        {
                            "name": db["DBInstanceIdentifier"],
                            "type": "Database Server",
                            "os": f"{db.get('Engine')} {db.get('EngineVersion')}",
                            "segment": f"Cloud-AWS-{region}",
                            "network_exposure": "internet-facing"
                            if db.get("PubliclyAccessible")
                            else "cloud",
                            "auth_method": "certificate",
                            "criticality": "high",
                            "data_classification": "Confidential",
                            "attrs": {
                                "engine": db.get("Engine"),
                                "engine_version": db.get("EngineVersion"),
                                "instance_class": db.get("DBInstanceClass"),
                                "publicly_accessible": db.get("PubliclyAccessible"),
                                "storage_encrypted": db.get("StorageEncrypted"),
                            },
                        }
                    )
        except ClientError as e:
            logger.error(f"RDS fetch failed: {e}")
        return out

    async def test_connection(self) -> bool:
        try:
            session = self._session(self.config.get("regions", ["us-east-1"])[0])
            sts = session.client("sts")
            await asyncio.to_thread(sts.get_caller_identity)
            return True
        except Exception as e:
            logger.error(f"AWS test failed: {e}")
            return False
