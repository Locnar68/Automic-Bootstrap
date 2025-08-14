# automic_bootstrap/orchestrators/deprovision.py
from __future__ import annotations

import argparse
import logging
import time
from pathlib import Path
from typing import Iterable, List, Tuple

import boto3
import botocore

log = logging.getLogger(__name__)

# ---------- helpers ----------
def setup_logging(verbosity: int = 1) -> None:
    level = logging.INFO if verbosity <= 1 else logging.DEBUG
    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    datefmt = "%H:%M:%S"
    logging.basicConfig(level=level, format=fmt, datefmt=datefmt)

def _banner(msg: str) -> None:
    line = "=" * max(30, len(msg) + 10)
    log.info("\n%s\n   %s\n%s\n", line, msg, line)

def _confirm(force: bool, prompt: str) -> None:
    if force:
        return
    ans = input(f"{prompt} Type 'yes' to continue: ").strip().lower()
    if ans != "yes":
        raise SystemExit("Aborted by user.")

# ---------- discovery ----------
def _find_instances(ec2, *, name_prefixes: Iterable[str], tag_key: str | None, tag_value: str | None) -> List[str]:
    filters = [
        {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]},
    ]
    if tag_key:
        if tag_value:
            filters.append({"Name": f"tag:{tag_key}", "Values": [tag_value]})
        else:
            filters.append({"Name": f"tag-key", "Values": [tag_key]})

    ids: List[str] = []
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate(Filters=filters):
        for res in page.get("Reservations", []):
            for inst in res.get("Instances", []):
                name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), "")
                if any(name.startswith(pfx) for pfx in name_prefixes) or (tag_key and any(
                    t["Key"] == tag_key and (not tag_value or t["Value"] == tag_value) for t in inst.get("Tags", [])
                )):
                    ids.append(inst["InstanceId"])
    return sorted(set(ids))

def _find_sg_id(ec2, *, sg_name: str, vpc_id: str | None) -> str | None:
    filters = [{"Name": "group-name", "Values": [sg_name]}]
    if vpc_id:
        filters.append({"Name": "vpc-id", "Values": [vpc_id]})
    resp = ec2.describe_security_groups(Filters=filters)
    if not resp["SecurityGroups"]:
        return None
    # If multiple, pick the first (we log it).
    return resp["SecurityGroups"][0]["GroupId"]

def _enis_referencing_sg(ec2, *, sg_id: str) -> List[str]:
    resp = ec2.describe_network_interfaces(
        Filters=[{"Name": "group-id", "Values": [sg_id]}]
    )
    return [eni["NetworkInterfaceId"] for eni in resp.get("NetworkInterfaces", [])]

def _find_eips_for_instances(ec2, ids: List[str]) -> List[Tuple[str, str | None]]:
    # Returns list of (allocation_id, association_id_or_none)
    if not ids:
        return []
    resp = ec2.describe_addresses()
    out = []
    for addr in resp.get("Addresses", []):
        inst_id = addr.get("InstanceId")
        if inst_id and inst_id in ids:
            out.append((addr.get("AllocationId"), addr.get("AssociationId")))
    return out

# ---------- actions ----------
def terminate_instances(ec2, ids: List[str], *, wait: bool = True) -> None:
    if not ids:
        log.info("No instances to terminate.")
        return
    log.info("Terminating instances: %s", ids)
    ec2.terminate_instances(InstanceIds=ids)
    if wait:
        waiter = ec2.get_waiter("instance_terminated")
        waiter.wait(InstanceIds=ids)
        log.info("Instances terminated.")

def release_eips(ec2, assoc: List[Tuple[str, str | None]]) -> None:
    if not assoc:
        log.info("No Elastic IPs associated with targeted instances.")
        return
    for alloc_id, assoc_id in assoc:
        try:
            if assoc_id:
                log.info("Disassociating EIP association %s", assoc_id)
                ec2.disassociate_address(AssociationId=assoc_id)
        except botocore.exceptions.ClientError as e:
            log.warning("Disassociate skipped: %s", e)
        try:
            if alloc_id:
                log.info("Releasing EIP allocation %s", alloc_id)
                ec2.release_address(AllocationId=alloc_id)
        except botocore.exceptions.ClientError as e:
            log.warning("Release skipped: %s", e)

def delete_security_group(ec2, *, sg_id: str, sg_name: str, max_wait_s: int = 90) -> None:
    if not sg_id:
        log.info("Security group '%s' not found.", sg_name)
        return
    log.info("Attempting delete of security group %s (%s)", sg_name, sg_id)

    # Retry loop to allow AWS to detach from ENIs after instance termination
    deadline = time.time() + max_wait_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            log.info("Security group deleted.")
            return
        except botocore.exceptions.ClientError as e:
            if "DependencyViolation" in str(e) and time.time() < deadline:
                enis = _enis_referencing_sg(ec2, sg_id=sg_id)
                if enis:
                    log.info("SG still attached to ENIs: %s ; waiting...", enis)
                else:
                    log.info("SG dependency still clearing; waiting...")
                time.sleep(5)
                continue
            log.error("Failed to delete SG %s (%s): %s", sg_name, sg_id, e)
            break

def delete_key_pair(ec2, *, key_name: str, pem_path: Path) -> None:
    try:
        log.info("Deleting AWS key pair: %s", key_name)
        ec2.delete_key_pair(KeyName=key_name)
        log.info("AWS key pair deleted.")
    except botocore.exceptions.ClientError as e:
        log.warning("Could not delete AWS key pair: %s", e)

    if pem_path.exists():
        try:
            pem_path.unlink()
            log.info("Local PEM removed: %s", pem_path)
        except Exception as e:
            log.warning("Failed to remove local PEM %s: %s", pem_path, e)
    else:
        log.info("Local PEM not found at: %s", pem_path)

# ---------- optional VPC teardown ----------
def delete_vpc(ec2, *, vpc_id: str, force: bool) -> None:
    """Dangerous; only use if this VPC is *dedicated* for Automic."""
    _banner(f"Deleting VPC {vpc_id}")
    _confirm(force, f"This will delete VPC {vpc_id} and attached resources.")
    # Detach & delete IGWs
    igws = ec2.describe_internet_gateways(
        Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}]
    )["InternetGateways"]
    for igw in igws:
        igw_id = igw["InternetGatewayId"]
        try:
            log.info("Detaching IGW %s", igw_id)
            ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
        except botocore.exceptions.ClientError:
            pass
        try:
            log.info("Deleting IGW %s", igw_id)
            ec2.delete_internet_gateway(InternetGatewayId=igw_id)
        except botocore.exceptions.ClientError:
            pass

    # Delete subnets
    subs = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    for sn in subs:
        sn_id = sn["SubnetId"]
        try:
            log.info("Deleting subnet %s", sn_id)
            ec2.delete_subnet(SubnetId=sn_id)
        except botocore.exceptions.ClientError as e:
            log.warning("Subnet %s deletion skipped: %s", sn_id, e)

    # Delete route tables (non-main)
    rts = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["RouteTables"]
    for rt in rts:
        # skip main
        assoc_main = any(a.get("Main") for a in rt.get("Associations", []))
        if assoc_main:
            continue
        try:
            log.info("Deleting route table %s", rt["RouteTableId"])
            ec2.delete_route_table(RouteTableId=rt["RouteTableId"])
        except botocore.exceptions.ClientError:
            pass

    # Delete SGs except default
    sgs = ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"]
    for sg in sgs:
        if sg["GroupName"] == "default":
            continue
        try:
            log.info("Deleting VPC SG %s (%s)", sg["GroupName"], sg["GroupId"])
            ec2.delete_security_group(GroupId=sg["GroupId"])
        except botocore.exceptions.ClientError:
            pass

    # Finally delete VPC
    try:
        log.info("Deleting VPC %s", vpc_id)
        ec2.delete_vpc(VpcId=vpc_id)
        log.info("VPC deleted.")
    except botocore.exceptions.ClientError as e:
        log.error("Failed to delete VPC %s: %s", vpc_id, e)

# ---------- CLI ----------
def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Automic AWS Deprovision")
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--name-prefix", action="append", default=["automic-", "AEDB", "AE", "AWI"],
                   help="Match EC2 Name tag starting with this prefix (can be repeated)")
    p.add_argument("--tag-key", default="AutomicStack", help="Extra tag key to match instances (optional)")
    p.add_argument("--tag-value", default=None, help="Tag value to match (optional)")
    p.add_argument("--sg-name", default="automic-sg", help="Security group name to delete")
    p.add_argument("--vpc-id", default=None, help="Security-group VPC ID (optional but recommended)")
    p.add_argument("--key-name", default="automic-key", help="AWS key pair name to delete")
    p.add_argument("--pem-dir", default=str(Path.home()), help="Local dir where <key-name>.pem sits")
    p.add_argument("--delete-vpc", action="store_true", help="(Dangerous) also delete the VPC by --vpc-id")
    p.add_argument("--force", action="store_true", help="Do not prompt for confirmation")
    p.add_argument("--verbosity", "-v", action="count", default=1)
    return p.parse_args(argv)

def main(argv=None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbosity)

    _banner("Automic AWS Deprovision")

    session = boto3.Session(region_name=args.region)
    ec2 = session.client("ec2")

    # 1) Discover instances
    _banner("Discover & Terminate EC2 Instances")
    ids = _find_instances(ec2,
                          name_prefixes=args.name_prefix,
                          tag_key=args.tag_key,
                          tag_value=args.tag_value)
    log.info("Matched instances: %s", ids)

    if ids:
        _confirm(args.force, f"Terminate {len(ids)} instance(s): {ids}?")
        # Release EIPs (if any) associated with those instances
        eips = _find_eips_for_instances(ec2, ids)
        if eips:
            _banner("Disassociate & Release Elastic IPs")
            release_eips(ec2, eips)

        terminate_instances(ec2, ids, wait=True)
    else:
        log.info("No matching instances found.")

    # 2) Delete SG
    _banner("Delete Security Group")
    sg_id = _find_sg_id(ec2, sg_name=args.sg_name, vpc_id=args.vpc_id)
    if sg_id:
        delete_security_group(ec2, sg_id=sg_id, sg_name=args.sg_name)
    else:
        log.info("Security group '%s' not found.", args.sg_name)

    # 3) Delete key pair + local PEM
    _banner("Delete Key Pair & Local PEM")
    pem = Path(args.pem_dir).expanduser() / f"{args.key_name}.pem"
    delete_key_pair(ec2, key_name=args.key_name, pem_path=pem)

    # 4) Optional VPC teardown
    if args.delete_vpc and args.vpc_id:
        delete_vpc(ec2, vpc_id=args.vpc_id, force=args.force)

    log.info("\nCleanup complete.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
