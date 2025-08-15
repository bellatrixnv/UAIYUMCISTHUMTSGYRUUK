import pytest
import boto3
from botocore.exceptions import ClientError

try:
    from moto import mock_aws
except ImportError:  # pragma: no cover
    mock_aws = None

from app.actions import S3BlockPublicAction

@pytest.mark.skipif(mock_aws is None, reason="moto not installed")
def test_preview_apply_rollback():
    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-bucket")
        action = S3BlockPublicAction("test-bucket", s3_client=s3)

        preview = action.preview()
        assert preview["bucket"] == "test-bucket"

        action.apply()
        cfg = s3.get_public_access_block(Bucket="test-bucket")
        assert cfg["PublicAccessBlockConfiguration"]["BlockPublicAcls"] is True

        action.rollback()
        with pytest.raises(ClientError):
            s3.get_public_access_block(Bucket="test-bucket")
