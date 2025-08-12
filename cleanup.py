#!/usr/bin/env python3
"""
Automic AWS Cleanup Script (Python Version)
Reverses the simplified bootstrap actions:
  - Terminates EC2 instances tagged by the launch script
  - Deletes the security group
  - Deletes the AWS key pair and local PEM file
"""
import os
import sys
import argparse
import logging
import time
from pathlib import Path

import boto3
import botocore

# --- Helpers ---
def banner(text):
    line = '=' * max(30, len(text) + 10)
    logging.info(f"\n{line}\n   {text}\n{line}\n")

def get_default(env_var, default):
    return os.environ.get(env_var, default)

# --- Cleanup Functions ---
def find_automic_instances(ec2, name_prefixes=['automic-', 'AEDB', 'AE', 'AWI']):
    resp = ec2.describe_instances(
        Filters=[{
            'Name': 'instance-state-name',
            'Values': ['pending', 'running', 'stopping', 'stopped']
        }]
    )
    ids = []
    for res in resp['Reservations']:
        for inst in res['Instances']:
            for tag in inst.get('Tags', []):
                if tag['Key'] == 'Name' and any(tag['Value'].startswith(p) for p in name_prefixes):
                    ids.append(inst['InstanceId'])
    return ids


def terminate_instances(ec2, ids, wait=True):
    if not ids:
        logging.info("No Automic instances found to terminate.")
        return
    logging.info(f"Terminating instances: {ids}")
    ec2.terminate_instances(InstanceIds=ids)
    if wait:
        waiter = ec2.get_waiter('instance_terminated')
        waiter.wait(InstanceIds=ids)
        logging.info("Instance termination complete.")


def delete_security_group(ec2, sg_name, vpc_id=None, wait_timeout=60):
    filters = [{'Name': 'group-name', 'Values': [sg_name]}]
    if vpc_id:
        filters.append({'Name': 'vpc-id', 'Values': [vpc_id]})

    resp = ec2.describe_security_groups(Filters=filters)
    if not resp['SecurityGroups']:
        logging.info(f"Security group '{sg_name}' not found.")
        return

    sg_id = resp['SecurityGroups'][0]['GroupId']
    logging.info(f"Found Security Group '{sg_name}' with ID: {sg_id}")

    # Attempt SG deletion immediately, no ENI check
    try:
        logging.info(f"Trying to delete security group: {sg_name} ({sg_id})")
        ec2.delete_security_group(GroupId=sg_id)
        logging.info("Security group deleted.")
    except botocore.exceptions.ClientError as e:
        logging.warning(f"Initial deletion failed: {e}")
        if "DependencyViolation" in str(e):
            logging.info("Waiting briefly before retry...")
            time.sleep(10)
            try:
                ec2.delete_security_group(GroupId=sg_id)
                logging.info("Security group deleted after retry.")
            except Exception as ex:
                logging.error(f"Force retry failed: {ex}")
        else:
            logging.error(f"Failed to delete security group: {e}")
def delete_key_pair(ec2, key_name, key_dir):
    # AWS key pair
    try:
        logging.info(f"Deleting AWS key pair: {key_name}")
        ec2.delete_key_pair(KeyName=key_name)
        logging.info("AWS key pair deleted.")
    except botocore.exceptions.ClientError as e:
        logging.warning(f"Could not delete AWS key pair: {e}")
    # Local PEM
    pem = Path(key_dir).expanduser() / f"{key_name}.pem"
    if pem.exists():
        try:
            logging.info(f"Removing local PEM: {pem}")
            pem.unlink()
            logging.info("Local PEM removed.")
        except Exception as e:
            logging.error(f"Failed to remove local PEM: {e}")
    else:
        logging.info("Local PEM not found.")

# --- Main ---

def main():
    parser = argparse.ArgumentParser(description="Automic AWS Cleanup Script")
    parser.add_argument('--region', default=get_default('AWS_REGION','us-east-1'))
    parser.add_argument('--sg-name', default=get_default('AUTOMIC_SGNAME','automic-sg'))
    parser.add_argument('--key-name', default=get_default('AUTOMIC_KEYNAME','automic-key'))
    parser.add_argument('--key-dir', default=str(Path.home()))
    parser.add_argument('--vpc-id', default=None)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(message)s')
    ec2 = boto3.client('ec2', region_name=args.region)

    banner("Terminating Automic EC2 Instances")
    ids = find_automic_instances(ec2)
    terminate_instances(ec2, ids)

    banner("Deleting Security Group")
    delete_security_group(ec2, args.sg_name, args.vpc_id)

    banner("Deleting Key Pair and PEM")
    delete_key_pair(ec2, args.key_name, args.key_dir)

    logging.info("\nCleanup complete.")

if __name__ == '__main__':
    main()
