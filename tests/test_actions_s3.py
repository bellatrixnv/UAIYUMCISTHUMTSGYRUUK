import json
import boto3
import pytest
from moto import mock_aws
from app.actions_s3 import S3BlockPublicAction

@mock_aws
def test_s3_block_public_preview_apply_rollback():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="my-bucket")

    # Put a permissive policy to prove we clean it up
    policy = {
        "Version":"2012-10-17",
        "Statement":[
            {"Sid":"PublicRead", "Effect":"Allow", "Principal":"*", "Action":"s3:GetObject", "Resource":"arn:aws:s3:::my-bucket/*"}
        ]
    }
    s3.put_bucket_policy(Bucket="my-bucket", Policy=json.dumps(policy))

    action = S3BlockPublicAction(bucket="my-bucket", region="us-east-1")
    prev = action.preview()
    assert prev["bucket"] == "my-bucket"
    assert prev["will_set_public_access_block"]["BlockPublicAcls"] is True

    out = action.apply()
    assert out["applied"] is True

    # Confirm PublicAccessBlock set
    pab = s3.get_public_access_block(Bucket="my-bucket")["PublicAccessBlockConfiguration"]
    assert all(pab.values())

    # Confirm policy cleaned (no Allow * principal)
    pol = s3.get_bucket_policy(Bucket="my-bucket")["Policy"]
    doc = json.loads(pol)
    for st in doc.get("Statement", []):
        assert not (st.get("Effect") == "Allow" and (st.get("Principal") == "*" or st.get("Principal") == {"AWS":"*"}))

    # Rollback works (best-effort)
    rb = action.rollback()
    assert rb["rolled_back"] is True
