import boto3, json, time
from botocore.config import Config

def assume(role_arn: str, external_id: str, session_name: str = "smbsec-cspm"):
    sts = boto3.client("sts", config=Config(retries={'max_attempts': 3}))
    resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name, ExternalId=external_id, DurationSeconds=1800)
    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]
    )

def s3_public_findings(sess):
    s3 = sess.client("s3", config=Config(retries={'max_attempts': 3}))
    out = []
    buckets = s3.list_buckets().get("Buckets", [])
    for b in buckets:
        name = b["Name"]
        public = False
        details = {}
        try:
            pab = s3.get_public_access_block(Bucket=name)
            details["PublicAccessBlock"] = pab.get("PublicAccessBlockConfiguration", {})
            cfg = details["PublicAccessBlock"]
            if not any(cfg.values()):
                public = True
        except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
            public = True
        except Exception as e:
            details["PublicAccessBlock_error"] = str(e)
        try:
            pol_status = s3.get_bucket_policy_status(Bucket=name)
            if pol_status.get("PolicyStatus", {}).get("IsPublic"):
                public = True
            details["PolicyStatus"] = pol_status
        except Exception as e:
            details["PolicyStatus_error"] = str(e)
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            grants = acl.get("Grants", [])
            for g in grants:
                grantee = g.get("Grantee", {})
                if grantee.get("URI","").endswith("/AllUsers") or grantee.get("URI","").endswith("/AuthenticatedUsers"):
                    public = True
            details["ACL"] = acl
        except Exception as e:
            details["ACL_error"] = str(e)
        if public:
            out.append({"resource": f"s3://{name}", "issue": "Public S3 bucket", "details": details})
    return out

def iam_admin_findings(sess):
    iam = sess.client("iam", config=Config(retries={'max_attempts': 3}))
    out = []
    admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    users = iam.list_users().get("Users", [])
    for u in users:
        name = u["UserName"]
        at = iam.list_attached_user_policies(UserName=name).get("AttachedPolicies", [])
        for p in at:
            if p["PolicyArn"] == admin_arn:
                out.append({"resource": f"iam:user/{name}", "issue": "User has AdministratorAccess", "details": p})
    groups = iam.list_groups().get("Groups", [])
    for g in groups:
        gname = g["GroupName"]
        at = iam.list_attached_group_policies(GroupName=gname).get("AttachedPolicies", [])
        for p in at:
            if p["PolicyArn"] == admin_arn:
                out.append({"resource": f"iam:group/{gname}", "issue": "Group has AdministratorAccess", "details": p})
    return out

def sg_open_findings(sess):
    ec2 = sess.client("ec2", config=Config(retries={'max_attempts': 3}))
    out = []
    resp = ec2.describe_security_groups()
    for sg in resp.get("SecurityGroups", []):
        for rule in sg.get("IpPermissions", []):
            for rng in rule.get("IpRanges", []):
                if rng.get("CidrIp") == "0.0.0.0/0":
                    port = rule.get("FromPort")
                    out.append({
                        "resource": f"sg:{sg['GroupId']}",
                        "issue": f"Security group allows 0.0.0.0/0 on port {port}",
                        "details": rule,
                    })
    return out

def run_checks(role_arn: str, external_id: str):
    sess = assume(role_arn, external_id)
    findings = []
    findings += s3_public_findings(sess)
    findings += iam_admin_findings(sess)
    findings += sg_open_findings(sess)
    return findings
