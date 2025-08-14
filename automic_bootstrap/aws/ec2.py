import logging
import os
import stat
import time
from pathlib import Path

import boto3
import botocore

log = logging.getLogger(__name__)


def ensure_vpc(ec2, vpc_id=None):
    if vpc_id:
        return vpc_id
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])["Vpcs"]
    if not vpcs:
        raise RuntimeError("No default VPC found; please specify --vpc-id")
    return vpcs[0]["VpcId"]


def ensure_security_group(ec2, vpc_id, sg_name):
    existing = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": [sg_name]},
        ]
    )["SecurityGroups"]
    if existing:
        return existing[0]["GroupId"]
    sg = ec2.create_security_group(
        GroupName=sg_name, Description="Automic Security Group", VpcId=vpc_id
    )
    sg_id = sg["GroupId"]
    ports = [22, 5432, 2217, 2218, 2219, 8080]
    for port in ports:
        while True:
            try:
                ec2.authorize_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[
                        {
                            "IpProtocol": "tcp",
                            "FromPort": port,
                            "ToPort": port,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                )
                break
            except botocore.exceptions.ClientError as e:
                if "InvalidPermission.Duplicate" in str(e):
                    break
                if "Throttling" in str(e):
                    time.sleep(2)
                    continue
                raise
    return sg_id


def _delete_key_file_safely(key_path: Path):
    try:
        if os.name == "nt":
            import ctypes

            ctypes.windll.kernel32.SetFileAttributesW(str(key_path), 0x80)
        key_path.chmod(stat.S_IWRITE | stat.S_IREAD)
        key_path.unlink(missing_ok=True)
    except Exception as e:
        log.warning(f"Could not delete key file: {e}")


def ensure_key_pair(name: str, key_path: Path, ec2):
    key_path = key_path.expanduser().resolve()
    try:
        ec2.describe_key_pairs(KeyNames=[name])
        ec2.delete_key_pair(KeyName=name)
    except botocore.exceptions.ClientError:
        pass
    _delete_key_file_safely(key_path)
    kp = ec2.create_key_pair(KeyName=name)
    key_path.write_text(kp["KeyMaterial"])
    key_path.chmod(0o600)
    return str(key_path)


def get_latest_ami(region: str):
    ssm = boto3.client("ssm", region_name=region)
    param = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64"
    return ssm.get_parameter(Name=param)["Parameter"]["Value"]


def launch_ec2_instance(ec2, name, instance_type, key_name, sg_id, ami_id, user_data):
    res = ec2.run_instances(
        ImageId=ami_id,
        InstanceType=instance_type,
        MinCount=1,
        MaxCount=1,
        KeyName=key_name,
        SecurityGroupIds=[sg_id],
        UserData=user_data,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    return res["Instances"][0]["InstanceId"]


def wait_for_instances(ec2, instance_ids):
    ec2.get_waiter("instance_running").wait(
        InstanceIds=instance_ids, WaiterConfig={"Delay": 15, "MaxAttempts": 40}
    )
    ec2.get_waiter("instance_status_ok").wait(
        InstanceIds=instance_ids, WaiterConfig={"Delay": 15, "MaxAttempts": 40}
    )


def get_instance_ip(ec2, instance_id):
    res = ec2.describe_instances(InstanceIds=[instance_id])
    return res["Reservations"][0]["Instances"][0]["PublicIpAddress"]
