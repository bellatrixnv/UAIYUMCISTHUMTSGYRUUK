import boto3
from moto import mock_aws
import app.cspm_aws as cspm

@mock_aws
def test_sg_open_findings_detects_open_ingress():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg_id = ec2.create_security_group(GroupName="sg", Description="test", VpcId=vpc_id)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
        }]
    )
    sess = boto3.Session(region_name="us-east-1")
    findings = cspm.sg_open_findings(sess)
    assert len(findings) == 1
    f = findings[0]
    assert f["resource"] == f"sg:{sg_id}"
    assert f["issue"] == "Security group allows 0.0.0.0/0 on port 22"

@mock_aws
def test_run_checks_includes_sg_findings(monkeypatch):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg_id = ec2.create_security_group(GroupName="sg", Description="test", VpcId=vpc_id)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 80,
            "ToPort": 80,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
        }]
    )
    sess = boto3.Session(region_name="us-east-1")
    monkeypatch.setattr(cspm, "assume", lambda role, ext: sess)
    monkeypatch.setattr(cspm, "s3_public_findings", lambda s: [])
    monkeypatch.setattr(cspm, "iam_admin_findings", lambda s: [])
    findings = cspm.run_checks("r", "e")
    assert any(f["resource"] == f"sg:{sg_id}" for f in findings)
