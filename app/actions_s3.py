from __future__ import annotations
import json
from dataclasses import dataclass
from typing import Dict, Any
import botocore
import boto3
from botocore.config import Config

@dataclass
class S3BlockPublicAction:
    bucket: str
    region: str | None = None

    def _client(self):
        return boto3.client("s3", region_name=self.region, config=Config(retries={"max_attempts": 5}))

    def preview(self) -> Dict[str, Any]:
        """
        Show what will be changed: enable PublicAccessBlock (all 4 flags = True).
        """
        desired = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True
        }
        return {"bucket": self.bucket, "will_set_public_access_block": desired}

    def apply(self) -> Dict[str, Any]:
        """
        Idempotently apply the PublicAccessBlock configuration.
        """
        s3 = self._client()
        desired = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True
        }
        s3.put_public_access_block(
            Bucket=self.bucket,
            PublicAccessBlockConfiguration=desired
        )
        # Optional: remove policy statements that allow public principal
        try:
            pol = s3.get_bucket_policy(Bucket=self.bucket)
            doc = json.loads(pol["Policy"])
            if "Statement" in doc:
                new_statements = []
                changed = False
                for st in doc["Statement"]:
                    principal = st.get("Principal")
                    effect = st.get("Effect", "Deny")
                    if effect == "Allow" and (principal == "*" or principal == {"AWS": "*"}):
                        changed = True
                        continue
                    new_statements.append(st)
                if changed:
                    doc["Statement"] = new_statements
                    s3.put_bucket_policy(Bucket=self.bucket, Policy=json.dumps(doc))
        except s3.exceptions.NoSuchBucketPolicy:
            pass

        return {"bucket": self.bucket, "applied": True}

    def rollback(self) -> Dict[str, Any]:
        """
        Rollback: remove PublicAccessBlock (NOT always safe; provided for symmetry).
        """
        s3 = self._client()
        try:
            s3.delete_public_access_block(Bucket=self.bucket)
            return {"bucket": self.bucket, "rolled_back": True}
        except botocore.exceptions.ClientError as e:
            return {"bucket": self.bucket, "rolled_back": False, "error": str(e)}
