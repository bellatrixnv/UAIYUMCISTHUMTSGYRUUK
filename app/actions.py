from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, Protocol
import boto3
from botocore.exceptions import ClientError

class Action(Protocol):
    def preview(self) -> Dict[str, Any]: ...
    def apply(self) -> Dict[str, Any]: ...
    def rollback(self) -> Dict[str, Any]: ...

@dataclass
class S3BlockPublicAction:
    bucket: str
    s3_client: boto3.client | None = None
    _previous: Dict[str, Any] | None = None

    def __post_init__(self):
        if self.s3_client is None:
            self.s3_client = boto3.client("s3")

    def preview(self) -> Dict[str, Any]:
        return {
            "action": "block_public_access",
            "bucket": self.bucket,
            "configuration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        }

    def apply(self) -> Dict[str, Any]:
        try:
            resp = self.s3_client.get_public_access_block(Bucket=self.bucket)
            self._previous = resp.get("PublicAccessBlockConfiguration", {})
        except ClientError:
            self._previous = {}
        config = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
        self.s3_client.put_public_access_block(
            Bucket=self.bucket, PublicAccessBlockConfiguration=config
        )
        return config

    def rollback(self) -> Dict[str, Any]:
        if self._previous is None:
            raise RuntimeError("apply() must be called before rollback()")
        if self._previous:
            self.s3_client.put_public_access_block(
                Bucket=self.bucket, PublicAccessBlockConfiguration=self._previous
            )
        else:
            try:
                self.s3_client.delete_public_access_block(Bucket=self.bucket)
            except ClientError:
                pass
        return self._previous
