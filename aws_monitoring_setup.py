#!/usr/bin/env python3
"""
AWS Monitoring Setup Script

This single-file setup script configures a production-ready AWS monitoring solution.
It runs securely from AWS CloudShell, prompts for approval before every API change,
automatically associates SSM IAM permissions with EC2 instances so they become managed,
provides an option to clean up pre-existing alarms, and implements all requested dashboards,
alarms, and notifications.
"""

import boto3
import sys
import argparse
import logging
import json
import time
import datetime
import zipfile
import io
import os
from botocore.exceptions import ClientError, BotoCoreError

# =============================================================================
# Logging & Global State
# =============================================================================

LOG_FILE = "deployment.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, mode='a'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("aws_monitoring_setup")

DRY_RUN = False
AUTO_APPROVE = False
CLEAN_ALARMS = False

AWS_ACCOUNT_ID = None
AWS_REGION = None
ADMIN_IDENTITY = None

DEFAULT_SNS_TOPIC_NAME = "InfrastructureAlerts"
LAMBDA_NOTIFIER_ROLE_NAME = "AWSMonitoring-LambdaNotifierRole"

INVENTORY = {
    "ec2": [],
    "rds": [],
    "lambda": [],
    "sns": [],
    "alarms": [],
    "dashboards": [],
    "log_groups": [],
    "iam_roles": [],
    "iam_policies": [],
    "eventbridge_rules": [],
    "acm_certs": [],
    "ssm_instances": [],
    "vpc": [],
    "subnets": [],
    "security_groups": [],
    "cw_agent_status": {},
    "s3_buckets": []
}

STATS = {
    "resources_discovered": 0,
    "resources_created": 0,
    "resources_updated": 0,
    "resources_skipped": 0,
    "resources_failed": 0
}

# =============================================================================
# Retry Decorator & Helpers
# =============================================================================

def with_retry(max_retries=3, backoff_factor=2):
    """Decorator to retry AWS API calls on transient or throttling errors."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            retries = 0
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except ClientError as e:
                    error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                    if error_code in ['Throttling', 'ThrottlingException', 'RequestLimitExceeded']:
                        sleep_time = backoff_factor ** retries
                        logger.warning(f"Throttled by AWS API ({error_code}). Retrying in {sleep_time}s...")
                        time.sleep(sleep_time)
                        retries += 1
                    else:
                        raise e
                except BotoCoreError as e:
                    sleep_time = backoff_factor ** retries
                    logger.warning(f"BotoCoreError: {e}. Retrying in {sleep_time}s...")
                    time.sleep(sleep_time)
                    retries += 1
            return func(*args, **kwargs)
        return wrapper
    return decorator

@with_retry()
def get_boto_client(service, region_name=None):
    if region_name:
        return boto3.client(service, region_name=region_name)
    return boto3.client(service)

def load_dotenv(filepath='.env'):
    """Loads environment variables from a .env file without external dependencies."""
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip().strip('"\'')
        print(f"[*] Successfully loaded environment variables from {filepath}")
    else:
        # Try relative to script dir just in case
        script_dir_env = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
        if os.path.exists(script_dir_env):
            with open(script_dir_env, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if '=' in line:
                        key, value = line.split('=', 1)
                        os.environ[key.strip()] = value.strip().strip('"\'')
            print(f"[*] Successfully loaded environment variables from {script_dir_env}")

def get_input(prompt, env_var):
    """Fetches input from environment variables first, then falls back to interactive prompt."""
    val = os.environ.get(env_var)
    if val is not None:
        return val
    try:
        return input(prompt).strip()
    except EOFError:
        return ""

# =============================================================================
# Approval Engine
# =============================================================================

def require_approval(action, service, resource, params, reason):
    """Prompts the administrator for approval before executing modifying operations."""
    global AUTO_APPROVE, DRY_RUN

    print(f"\n{'-'*80}")
    print(f"ACTION REQUIRED : {action}")
    print(f"AWS Service     : {service}")
    print(f"Target Resource : {resource}")
    print(f"Parameters      : {json.dumps(params, default=str, indent=2)}")
    print(f"Reason          : {reason}")
    print(f"{'-'*80}")

    if DRY_RUN:
        print("[DRY-RUN] Action skipped.")
        logger.info(f"DRY RUN SKIPPED: {action} on {service} for {resource}")
        return False

    if AUTO_APPROVE:
        print("[AUTO-APPROVED]")
        logger.info(f"AUTO-APPROVED: {action} on {service} for {resource}")
        return True

    while True:
        try:
            choice = input("\nApprove? [Y] Yes | [N] No | [A] Yes to All | [Q] Quit : ").strip().upper()
        except EOFError:
            logger.error("EOF encountered. Exiting.")
            sys.exit(1)

        if choice == 'Y':
            logger.info(f"APPROVED: {action} on {service} for {resource}")
            return True
        elif choice == 'N':
            print("Action skipped by administrator.")
            logger.warning(f"REJECTED: {action} on {service} for {resource}")
            STATS["resources_skipped"] += 1
            return False
        elif choice == 'A':
            AUTO_APPROVE = True
            print("Auto-approve enabled for all remaining actions.")
            logger.info(f"AUTO-APPROVED ENABLED: {action} on {service} for {resource}")
            return True
        elif choice == 'Q':
            print("Exiting immediately as requested.")
            logger.info("Administrator requested quit.")
            sys.exit(0)
        else:
            print("Invalid choice. Please enter Y, N, A, or Q.")

def confirm_existing_resource(resource_type, resource_name):
    """Prompts the administrator on how to handle an existing resource."""
    global AUTO_APPROVE, DRY_RUN

    if DRY_RUN:
        return 'SKIP'
    if AUTO_APPROVE:
        return 'UPDATE'

    print(f"\n{'-'*80}")
    print(f"EXISTING RESOURCE DETECTED: {resource_type} -> {resource_name}")
    print(f"{'-'*80}")

    while True:
        try:
            choice = input("Action? [K] Keep | [U] Update | [R] Replace | [S] Skip : ").strip().upper()
        except EOFError:
            logger.error("EOF encountered. Exiting.")
            sys.exit(1)

        if choice == 'K':
            return 'KEEP'
        elif choice == 'U':
            return 'UPDATE'
        elif choice == 'R':
            return 'REPLACE'
        elif choice == 'S':
            return 'SKIP'
        else:
            print("Invalid choice. Please enter K, U, R, or S.")

# =============================================================================
# Discovery Phase
# =============================================================================

def validate_identity():
    """Validates the current AWS credentials and populates global config state."""
    global AWS_ACCOUNT_ID, AWS_REGION, ADMIN_IDENTITY
    try:
        sts = get_boto_client('sts')
        identity = sts.get_caller_identity()
        AWS_ACCOUNT_ID = identity['Account']
        ADMIN_IDENTITY = identity['Arn']
        
        session = boto3.session.Session()
        AWS_REGION = session.region_name
        
        logger.info(f"Identity Validated - Account: {AWS_ACCOUNT_ID}")
        logger.info(f"Identity Validated - Region: {AWS_REGION}")
        logger.info(f"Identity Validated - User ARN: {ADMIN_IDENTITY}")
        
    except ClientError as e:
        logger.error(f"Failed to validate AWS credentials: {e}")
        print("\nERROR: Unable to validate AWS identity. Check credentials.")
        sys.exit(1)

def run_discovery():
    """Discovers resources in the current region."""
    print("\n--- Starting Environment Discovery ---")
    ec2 = get_boto_client('ec2')
    rds = get_boto_client('rds')
    ssm = get_boto_client('ssm')
    iam = get_boto_client('iam')
    acm = get_boto_client('acm')
    sns = get_boto_client('sns')
    cw = get_boto_client('cloudwatch')
    lmb = get_boto_client('lambda')
    logs = get_boto_client('logs')
    events = get_boto_client('events')

    # 1. Discover VPC / Subnets / SGs
    try:
        for page in ec2.get_paginator('describe_vpcs').paginate():
            for vpc in page.get('Vpcs', []):
                INVENTORY['vpc'].append(vpc['VpcId'])
        for page in ec2.get_paginator('describe_subnets').paginate():
            for subnet in page.get('Subnets', []):
                INVENTORY['subnets'].append(subnet['SubnetId'])
        for page in ec2.get_paginator('describe_security_groups').paginate():
            for sg in page.get('SecurityGroups', []):
                INVENTORY['security_groups'].append(sg['GroupId'])
    except Exception as e:
        logger.error(f"VPC Discovery Error: {e}")

    # 2. Discover EC2
    try:
        for page in ec2.get_paginator('describe_instances').paginate():
            for res in page.get('Reservations', []):
                for inst in res.get('Instances', []):
                    if inst['State']['Name'] in ['running', 'stopped']:
                        name = "Unknown"
                        for tag in inst.get('Tags', []):
                            if tag['Key'] == 'Name':
                                name = tag['Value']
                        INVENTORY['ec2'].append({
                            "Id": inst['InstanceId'],
                            "Name": name,
                            "State": inst['State']['Name'],
                            "Type": inst.get('InstanceType', 'unknown')
                        })
    except Exception as e:
        logger.error(f"EC2 Discovery Error: {e}")

    # 3. Discover RDS
    try:
        for page in rds.get_paginator('describe_db_instances').paginate():
            for db in page.get('DBInstances', []):
                INVENTORY['rds'].append({
                    "Id": db['DBInstanceIdentifier'],
                    "Engine": db['Engine'],
                    "Status": db['DBInstanceStatus']
                })
    except Exception as e:
        logger.error(f"RDS Discovery Error: {e}")

    # 4. Discover SSM Managed Instances
    try:
        for page in ssm.get_paginator('describe_instance_information').paginate():
            for inst in page.get('InstanceInformationList', []):
                INVENTORY['ssm_instances'].append(inst['InstanceId'])
    except Exception as e:
        logger.error(f"SSM Discovery Error: {e}")

    # 5. Discover IAM Roles & Customer-Managed Policies
    try:
        for page in iam.get_paginator('list_roles').paginate():
            for role in page.get('Roles', []):
                INVENTORY['iam_roles'].append(role['RoleName'])
        for page in iam.get_paginator('list_policies').paginate(Scope='Local'):
            for policy in page.get('Policies', []):
                INVENTORY['iam_policies'].append(policy['Arn'])
    except Exception as e:
        logger.error(f"IAM Discovery Error: {e}")

    # 6. Discover ACM Certs
    try:
        for page in acm.get_paginator('list_certificates').paginate():
            for cert in page.get('CertificateSummaryList', []):
                INVENTORY['acm_certs'].append({
                    "Arn": cert['CertificateArn'],
                    "DomainName": cert['DomainName']
                })
    except Exception as e:
        logger.error(f"ACM Discovery Error: {e}")

    # 7. Discover SNS Topics
    try:
        for page in sns.get_paginator('list_topics').paginate():
            for topic in page.get('Topics', []):
                INVENTORY['sns'].append(topic['TopicArn'])
    except Exception as e:
        logger.error(f"SNS Discovery Error: {e}")

    # 8. Discover Lambda Functions
    try:
        for page in lmb.get_paginator('list_functions').paginate():
            for func in page.get('Functions', []):
                INVENTORY['lambda'].append(func['FunctionName'])
    except Exception as e:
        logger.error(f"Lambda Discovery Error: {e}")

    # 9. Discover CloudWatch Alarms & Dashboards & Log Groups
    try:
        for page in cw.get_paginator('describe_alarms').paginate():
            for alarm in page.get('MetricAlarms', []):
                INVENTORY['alarms'].append(alarm['AlarmName'])
        for page in cw.get_paginator('list_dashboards').paginate():
            for d in page.get('DashboardEntries', []):
                INVENTORY['dashboards'].append(d['DashboardName'])
        for page in logs.get_paginator('describe_log_groups').paginate():
            for lg in page.get('logGroups', []):
                INVENTORY['log_groups'].append(lg['logGroupName'])
    except Exception as e:
        logger.error(f"CloudWatch Discovery Error: {e}")

    # 10. Discover EventBridge Rules
    try:
        for page in events.get_paginator('list_rules').paginate():
            for rule in page.get('Rules', []):
                INVENTORY['eventbridge_rules'].append(rule['Name'])
    except Exception as e:
        logger.error(f"EventBridge Discovery Error: {e}")

    # 11. Discover S3 Buckets
    try:
        s3 = get_boto_client('s3')
        for bucket in s3.list_buckets().get('Buckets', []):
            INVENTORY['s3_buckets'].append(bucket['Name'])
    except Exception as e:
        logger.error(f"S3 Discovery Error: {e}")

    # 12. Check CW Agent Active Status
    for inst in INVENTORY['ec2']:
        inst_id = inst['Id']
        INVENTORY['cw_agent_status'][inst_id] = "Not Installed / Offline"
        
    try:
        for page in cw.get_paginator('list_metrics').paginate(Namespace="CWAgent"):
            for m in page.get('Metrics', []):
                for d in m.get('Dimensions', []):
                    if d['Name'] == 'InstanceId':
                        i_id = d['Value']
                        if i_id in INVENTORY['cw_agent_status']:
                            INVENTORY['cw_agent_status'][i_id] = "Running (Active Metrics)"
    except Exception as e:
        logger.warning(f"Could not scan CWAgent active metrics: {e}")

    # Print Summary Inventory
    print("\n" + "="*80)
    print(" AWS INFRASTRUCTURE INVENTORY REPORT ")
    print("="*80)
    print(f"VPCs Discovered       : {len(INVENTORY['vpc'])}")
    print(f"Subnets Discovered    : {len(INVENTORY['subnets'])}")
    print(f"Security Groups       : {len(INVENTORY['security_groups'])}")
    print("-" * 80)
    print(f"EC2 Instances Found   : {len(INVENTORY['ec2'])}")
    for inst in INVENTORY['ec2']:
        status = INVENTORY['cw_agent_status'].get(inst['Id'], 'Unknown')
        print(f"  - {inst['Id']} | Name: {inst['Name']} | State: {inst['State']} | CW Agent: {status}")
    print(f"RDS Instances Found   : {len(INVENTORY['rds'])}")
    for db in INVENTORY['rds']:
        print(f"  - {db['Id']} | Engine: {db['Engine']} | Status: {db['Status']}")
    print(f"ACM Certificates      : {len(INVENTORY['acm_certs'])}")
    for cert in INVENTORY['acm_certs']:
        print(f"  - Domain: {cert['DomainName']} | Arn: {cert['Arn'].split('/')[-1]}")
    print("-" * 80)
    print(f"Lambda Functions      : {len(INVENTORY['lambda'])}")
    print(f"SNS Topics            : {len(INVENTORY['sns'])}")
    print(f"CloudWatch Alarms     : {len(INVENTORY['alarms'])}")
    print(f"CloudWatch Log Groups : {len(INVENTORY['log_groups'])}")
    print(f"CloudWatch Dashboards : {len(INVENTORY['dashboards'])}")
    print(f"IAM Roles             : {len(INVENTORY['iam_roles'])}")
    print(f"IAM Policies          : {len(INVENTORY['iam_policies'])}")
    print(f"EventBridge Rules     : {len(INVENTORY['eventbridge_rules'])}")
    print(f"SSM Managed Instances : {len(INVENTORY['ssm_instances'])}")
    print("="*80 + "\n")

    total_discovered = sum(len(v) if isinstance(v, list) else len(v.keys()) for v in INVENTORY.values())
    STATS['resources_discovered'] = total_discovered

# =============================================================================
# Alarm Cleanup Logic
# =============================================================================

def delete_old_alarms():
    """Scans and deletes pre-existing monitoring alarms created by this script."""
    cw = get_boto_client('cloudwatch')
    logger.info("Scanning for old monitoring alarms to delete...")
    
    prefixes = [
        "EC2-CPU-", "EC2-StatusCheck-", "EC2-NetworkOut-", "EC2-Memory-", "EC2-Swap-",
        "EC2-DiskUsed-", "EC2-DiskInodes-", "Web-ProcessDown-", "DB-ProcessDown-",
        "RDS-CPU-", "RDS-StorageLow-", "RDS-Connections-", "RDS-ReplicationLag-",
        "Synthetics-Failed-", "ACM-Expiry-", "SSL-Expiry-", "SSL-Check-"
    ]
    
    matching_alarms = []
    try:
        paginator = cw.get_paginator('describe_alarms')
        for page in paginator.paginate():
            for alarm in page.get('MetricAlarms', []):
                name = alarm['AlarmName']
                if any(name.startswith(p) for p in prefixes):
                    matching_alarms.append(name)
    except Exception as e:
        logger.error(f"Failed to scan existing alarms: {e}")
        return

    if not matching_alarms:
        logger.info("No matching pre-existing monitoring alarms found.")
        return
        
    print(f"\nDiscovered {len(matching_alarms)} old monitoring alarms:")
    for name in matching_alarms:
        print(f"  - {name}")
        
    if require_approval(
        action="DeleteAlarms",
        service="CloudWatch",
        resource=f"{len(matching_alarms)} alarms",
        params={"AlarmNames": matching_alarms},
        reason="Deletes existing alarms created by this script to reset the monitoring configurations."
    ):
        try:
            chunk_size = 100
            for i in range(0, len(matching_alarms), chunk_size):
                chunk = matching_alarms[i:i+chunk_size]
                cw.delete_alarms(AlarmNames=chunk)
            logger.info(f"Successfully deleted {len(matching_alarms)} old alarms.")
            INVENTORY['alarms'] = [a for a in INVENTORY['alarms'] if a not in matching_alarms]
        except Exception as e:
            logger.error(f"Failed to delete old alarms: {e}")

# =============================================================================
# Auto SSM Configuration for EC2
# =============================================================================

def configure_ec2_ssm_permissions(instance_id):
    """Automatically assigns SSM permissions (Instance Profile) to the EC2 instance."""
    ec2 = get_boto_client('ec2')
    iam = get_boto_client('iam')
    
    logger.info(f"Checking SSM permissions configuration for EC2 Instance: {instance_id}")
    
    existing_profile = None
    try:
        associations = ec2.describe_iam_instance_profile_associations(
            Filters=[{'Name': 'instance-id', 'Values': [instance_id]}]
        )
        if associations.get('IamInstanceProfileAssociations'):
            assoc = associations['IamInstanceProfileAssociations'][0]
            if assoc.get('State') == 'associated':
                existing_profile = assoc['IamInstanceProfile']
    except Exception as e:
        logger.warning(f"Could not describe IAM associations for {instance_id}: {e}")
        
    policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    cw_policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
    
    if existing_profile:
        # If it has an existing profile, find the roles attached and attach the policy
        profile_name = existing_profile.get('Arn', '').split('/')[-1]
        logger.info(f"Instance {instance_id} has existing IAM profile: {profile_name}")
        
        try:
            profile_info = iam.get_instance_profile(InstanceProfileName=profile_name)
            roles = profile_info['InstanceProfile'].get('Roles', [])
            for r in roles:
                role_name = r['RoleName']
                if require_approval(
                    action="AttachRolePolicy",
                    service="IAM",
                    resource=role_name,
                    params={"PolicyArn": policy_arn},
                    reason=f"Ensures the existing EC2 role '{role_name}' has SSM permissions so the instance becomes SSM-managed."
                ):
                    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
                    iam.attach_role_policy(RoleName=role_name, PolicyArn=cw_policy_arn)
                    logger.info(f"Attached SSM & CloudWatch Agent policies to existing role '{role_name}'")
        except Exception as e:
            logger.error(f"Failed to verify/attach SSM and CloudWatch Agent policies to existing profile roles for {instance_id}: {e}")
            
    else:
        # Create default SSM Role & Instance Profile and associate
        default_role_name = "AWSMonitoring-EC2InstanceRole"
        default_profile_name = "AWSMonitoring-EC2InstanceProfile"
        
        role_exists = False
        try:
            iam.get_role(RoleName=default_role_name)
            role_exists = True
        except iam.exceptions.NoSuchEntityException:
            pass
            
        if not role_exists:
            assume_policy = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }]
            }
            if require_approval(
                action="CreateRole",
                service="IAM",
                resource=default_role_name,
                params={"RoleName": default_role_name},
                reason="Creates default role for EC2 instances to communicate with Systems Manager (SSM)."
            ):
                try:
                    iam.create_role(
                        RoleName=default_role_name,
                        AssumeRolePolicyDocument=json.dumps(assume_policy),
                        Description="Default EC2 role created by AWS Monitoring Deployment"
                    )
                    logger.info(f"Created role {default_role_name}")
                except Exception as e:
                    logger.error(f"Failed to create role {default_role_name}: {e}")
                    return
                    
        # Attach policies to default role
        try:
            iam.attach_role_policy(RoleName=default_role_name, PolicyArn=policy_arn)
            iam.attach_role_policy(RoleName=default_role_name, PolicyArn=cw_policy_arn)
        except Exception as e:
            logger.error(f"Failed to attach policies to {default_role_name}: {e}")
            
        # Create Instance Profile if not exists
        profile_exists = False
        try:
            iam.get_instance_profile(InstanceProfileName=default_profile_name)
            profile_exists = True
        except iam.exceptions.NoSuchEntityException:
            pass
            
        if not profile_exists:
            if require_approval(
                action="CreateInstanceProfile",
                service="IAM",
                resource=default_profile_name,
                params={"InstanceProfileName": default_profile_name},
                reason="Creates default instance profile wrapper for the EC2 role."
            ):
                try:
                    iam.create_instance_profile(InstanceProfileName=default_profile_name)
                    logger.info(f"Created instance profile {default_profile_name}")
                except Exception as e:
                    logger.error(f"Failed to create instance profile {default_profile_name}: {e}")
                    return
                    
        # Add role to profile if not already added
        try:
            prof = iam.get_instance_profile(InstanceProfileName=default_profile_name)
            roles_in_prof = [r['RoleName'] for r in prof['InstanceProfile'].get('Roles', [])]
            if default_role_name not in roles_in_prof:
                if require_approval(
                    action="AddRoleToInstanceProfile",
                    service="IAM",
                    resource=default_profile_name,
                    params={"RoleName": default_role_name},
                    reason="Links the EC2 SSM role to the instance profile."
                ):
                    iam.add_role_to_instance_profile(
                        InstanceProfileName=default_profile_name,
                        RoleName=default_role_name
                    )
                    logger.info(f"Added role {default_role_name} to instance profile {default_profile_name}")
                    time.sleep(5)
        except Exception as e:
            logger.error(f"Failed to link role to profile: {e}")
            
        # Associate Profile with Instance
        if require_approval(
            action="AssociateIamInstanceProfile",
            service="EC2",
            resource=instance_id,
            params={"IamInstanceProfile": {"Name": default_profile_name}},
            reason=f"Associates SSM permissions to EC2 Instance {instance_id} to make it SSM-managed."
        ):
            try:
                ec2.associate_iam_instance_profile(
                    IamInstanceProfile={'Name': default_profile_name},
                    InstanceId=instance_id
                )
                logger.info(f"Associated instance profile to {instance_id}. Note: It may take 1-2 minutes for SSM agent to check in.")
            except Exception as e:
                logger.error(f"Failed to associate instance profile to {instance_id}: {e}")

# =============================================================================
# Deployment Logic
# =============================================================================

def setup_iam():
    """Sets up the Lambda/Synthetics Execution Role."""
    print("\n--- Configuring IAM Roles ---")
    iam = get_boto_client('iam')
    role_name = LAMBDA_NOTIFIER_ROLE_NAME
    
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", 
            "Principal": {
                "Service": [
                    "lambda.amazonaws.com",
                    "synthetics.amazonaws.com"
                ]
            }, 
            "Action": "sts:AssumeRole"
        }]
    }

    if role_name in INVENTORY['iam_roles']:
        action = confirm_existing_resource("IAM Role", role_name)
        if action in ('SKIP', 'KEEP'):
            logger.info(f"{'Skipping' if action == 'SKIP' else 'Keeping'} existing role: {role_name}")
            return iam.get_role(RoleName=role_name)['Role']['Arn']
            
    if require_approval(
        action="CreateRole",
        service="IAM",
        resource=role_name,
        params={"RoleName": role_name},
        reason="Required for Lambda functions and Synthetics Canaries to execute, store/read webhook secrets, and write results."
    ):
        try:
            try:
                role = iam.get_role(RoleName=role_name)
                role_arn = role['Role']['Arn']
                logger.info(f"IAM Role {role_name} already exists. Updating trust policy and permissions.")
                iam.update_assume_role_policy(
                    RoleName=role_name,
                    PolicyDocument=json.dumps(assume_role_policy)
                )
            except iam.exceptions.NoSuchEntityException:
                role = iam.create_role(
                    RoleName=role_name,
                    AssumeRolePolicyDocument=json.dumps(assume_role_policy),
                    Description="Role for AWS Monitoring Lambda and Synthetics Integrations"
                )
                role_arn = role['Role']['Arn']
                STATS['resources_created'] += 1

            # Attach AWSLambdaBasicExecutionRole
            iam.attach_role_policy(
                RoleName=role_name, 
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
            )
            
            # Policy to read webhooks from SSM Parameter Store
            ssm_policy = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow", 
                    "Action": ["ssm:GetParameter", "secretsmanager:GetSecretValue"], 
                    "Resource": "*"
                }]
            }
            iam.put_role_policy(
                RoleName=role_name, 
                PolicyName="SSMReadPolicy", 
                PolicyDocument=json.dumps(ssm_policy)
            )
            
            # Policy to check CloudWatch (for synthetics/status)
            cw_policy = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow", 
                    "Action": ["cloudwatch:PutMetricData"], 
                    "Resource": "*"
                }]
            }
            iam.put_role_policy(
                RoleName=role_name,
                PolicyName="CWMetricsPolicy",
                PolicyDocument=json.dumps(cw_policy)
            )

            # Policy for Synthetics to access S3 artifacts bucket and write execution logs
            synthetics_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:PutObject",
                            "s3:GetObject",
                            "s3:GetBucketLocation",
                            "s3:ListBucket"
                        ],
                        "Resource": [
                            f"arn:aws:s3:::cw-synthetics-artifacts-{AWS_ACCOUNT_ID}-{AWS_REGION}",
                            f"arn:aws:s3:::cw-synthetics-artifacts-{AWS_ACCOUNT_ID}-{AWS_REGION}/*"
                        ]
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents"
                        ],
                        "Resource": f"arn:aws:logs:{AWS_REGION}:{AWS_ACCOUNT_ID}:*"
                    }
                ]
            }
            iam.put_role_policy(
                RoleName=role_name,
                PolicyName="SyntheticsS3LogsPolicy",
                PolicyDocument=json.dumps(synthetics_policy)
            )

            # Policy to allow publishing to SNS
            sns_policy = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow", 
                    "Action": ["sns:Publish"], 
                    "Resource": "*"
                }]
            }
            iam.put_role_policy(
                RoleName=role_name, 
                PolicyName="SNSPublishPolicy", 
                PolicyDocument=json.dumps(sns_policy)
            )

            logger.info(f"Successfully configured IAM Role: {role_name}")
            return role_arn
            
        except Exception as e:
            logger.error(f"Failed to setup IAM Role {role_name}: {e}")
            STATS['resources_failed'] += 1
            
    return ""

def setup_sns():
    """Configures the alerting SNS topic and subscriptions."""
    print("\n--- Configuring SNS Alert Pipeline ---")
    sns = get_boto_client('sns')
    topic_name = DEFAULT_SNS_TOPIC_NAME
    
    existing_arn = next((arn for arn in INVENTORY['sns'] if topic_name in arn), None)
    if existing_arn:
        action = confirm_existing_resource("SNS Topic", topic_name)
        if action in ('SKIP', 'KEEP'):
            logger.info(f"{'Skipping' if action == 'SKIP' else 'Keeping'} existing SNS Topic: {topic_name}")
            return existing_arn
            
    if require_approval(
        action="CreateTopic",
        service="SNS",
        resource=topic_name,
        params={"Name": topic_name},
        reason="Creates the central SNS topic to which all CloudWatch Alarms will publish."
    ):
        try:
            response = sns.create_topic(Name=topic_name)
            topic_arn = response['TopicArn']
            STATS['resources_created'] += 1
            if topic_arn not in INVENTORY['sns']:
                INVENTORY['sns'].append(topic_arn)
            logger.info(f"SNS Topic created/verified: {topic_arn}")
            
            if not DRY_RUN:
                emails = get_input("Enter email addresses to subscribe to alerts (comma-separated, blank to skip): ", "ALERT_EMAILS")
                if emails:
                    for email in emails.split(','):
                        email = email.strip()
                        if email:
                            sns.subscribe(TopicArn=topic_arn, Protocol='email', Endpoint=email)
                            logger.info(f"Subscribed {email} to {topic_name}")
                            
            return topic_arn
        except Exception as e:
            logger.error(f"Failed to create SNS topic {topic_name}: {e}")
            STATS['resources_failed'] += 1
    return ""

def store_webhook(service_name, param_name, env_var):
    if DRY_RUN:
        print(f"[DRY-RUN] Would prompt for {service_name} webhook and store as {param_name}")
        return

    val = get_input(f"Enter {service_name} Webhook URL / Token (leave blank to skip): ", env_var)
        
    if not val:
        return
        
    if require_approval(
        action="PutParameter",
        service="SSM Parameter Store",
        resource=param_name,
        params={"Type": "SecureString", "Overwrite": True},
        reason=f"Securely stores the {service_name} credential for Lambda notifications."
    ):
        try:
            ssm = get_boto_client('ssm')
            ssm.put_parameter(
                Name=param_name, 
                Value=val, 
                Type='SecureString', 
                Overwrite=True
            )
            STATS['resources_created'] += 1
            logger.info(f"Stored securely: {param_name}")
        except Exception as e:
            logger.error(f"Failed to store {param_name}: {e}")
            STATS['resources_failed'] += 1

def configure_ssm_webhooks():
    print("\n--- Configuring Webhook Integrations ---")
    store_webhook("Slack", "/monitoring/slack_webhook", "SLACK_WEBHOOK")
    store_webhook("Microsoft Teams", "/monitoring/teams_webhook", "TEAMS_WEBHOOK")
    store_webhook("Telegram Bot Token", "/monitoring/telegram_token", "TELEGRAM_TOKEN")
    store_webhook("Telegram Chat ID", "/monitoring/telegram_chat_id", "TELEGRAM_CHAT_ID")

# =============================================================================
# Notifier Lambda
# =============================================================================

LAMBDA_NOTIFIER_CODE = """
import json
import os
import urllib.request
import urllib.error
import boto3

def get_ssm_param(name):
    try:
        ssm = boto3.client('ssm')
        res = ssm.get_parameter(Name=name, WithDecryption=True)
        return res['Parameter']['Value']
    except Exception as e:
        print(f"SSM Fetch Error for {name}: {e}")
        return None

def lambda_handler(event, context):
    slack_url = get_ssm_param('/monitoring/slack_webhook')
    teams_url = get_ssm_param('/monitoring/teams_webhook')
    tg_token = get_ssm_param('/monitoring/telegram_token')
    tg_chat = get_ssm_param('/monitoring/telegram_chat_id')
    
    for record in event['Records']:
        msg = record['Sns']['Message']
        try:
            msg_dict = json.loads(msg)
            alarm_name = msg_dict.get('AlarmName', 'Unknown Alarm')
            new_state = msg_dict.get('NewStateValue', 'UNKNOWN')
            reason = msg_dict.get('NewStateReason', '')
            formatted_msg = f"*{new_state}* | {alarm_name}\\n{reason}"
        except:
            formatted_msg = msg

        payload = {"text": formatted_msg}
        data = json.dumps(payload).encode('utf-8')
        
        if slack_url:
            try:
                req = urllib.request.Request(slack_url, data=data, headers={'Content-Type': 'application/json'})
                urllib.request.urlopen(req)
            except Exception as e:
                print("Slack Error:", e)
                
        if teams_url:
            try:
                req = urllib.request.Request(teams_url, data=data, headers={'Content-Type': 'application/json'})
                urllib.request.urlopen(req)
            except Exception as e:
                print("Teams Error:", e)
                
        if tg_token and tg_chat:
            tg_url = f"https://api.telegram.org/bot{tg_token}/sendMessage"
            tg_payload = json.dumps({"chat_id": tg_chat, "text": formatted_msg}).encode('utf-8')
            try:
                req = urllib.request.Request(tg_url, data=tg_payload, headers={'Content-Type': 'application/json'})
                urllib.request.urlopen(req)
            except Exception as e:
                print("Telegram Error:", e)

    return {"statusCode": 200, "body": "Success"}
"""

def deploy_lambda_notifier(role_arn, sns_topic_arn):
    if not role_arn:
        logger.warning("No IAM Role provided. Skipping Lambda deployment.")
        return
        
    lmb = get_boto_client('lambda')
    func_name = "AWSMonitoringNotifier"
    
    if func_name in INVENTORY['lambda']:
        action = confirm_existing_resource("Lambda Function", func_name)
        if action == 'SKIP':
            logger.info(f"Skipping existing Lambda: {func_name}")
            return
            
    if require_approval(
        action="Create/Update Function",
        service="Lambda",
        resource=func_name,
        params={"Runtime": "python3.11", "Role": role_arn},
        reason="Deploys the Python script to format and forward SNS alerts to webhooks."
    ):
        zip_bytes = create_lambda_zip(LAMBDA_NOTIFIER_CODE)
        
        try:
            time.sleep(5)
            try:
                lmb.get_function(FunctionName=func_name)
                logger.info(f"Function {func_name} exists. Updating code.")
                lmb.update_function_code(FunctionName=func_name, ZipFile=zip_bytes)
                STATS['resources_updated'] += 1
                func_arn = lmb.get_function(FunctionName=func_name)['Configuration']['FunctionArn']
            except lmb.exceptions.ResourceNotFoundException:
                retries = 6
                while retries > 0:
                    try:
                        res = lmb.create_function(
                            FunctionName=func_name,
                            Runtime='python3.11',
                            Role=role_arn,
                            Handler='index.lambda_handler',
                            Code={'ZipFile': zip_bytes},
                            Timeout=30
                        )
                        func_arn = res['FunctionArn']
                        STATS['resources_created'] += 1
                        break
                    except ClientError as e:
                        if e.response.get('Error', {}).get('Code') == 'InvalidParameterValueException' and 'cannot be assumed' in e.response.get('Error', {}).get('Message', ''):
                            logger.warning("IAM role is still propagating. Retrying in 5 seconds...")
                            time.sleep(5)
                            retries -= 1
                        else:
                            raise e
                else:
                    raise Exception("Failed to deploy Lambda: IAM role propagation timed out.")

            if sns_topic_arn:
                sns = get_boto_client('sns')
                sns.subscribe(TopicArn=sns_topic_arn, Protocol='lambda', Endpoint=func_arn)
                
                try:
                    lmb.add_permission(
                        FunctionName=func_name,
                        StatementId="sns-invoke",
                        Action="lambda:InvokeFunction",
                        Principal="sns.amazonaws.com",
                        SourceArn=sns_topic_arn
                    )
                except lmb.exceptions.ResourceConflictException:
                    pass

            logger.info(f"Successfully deployed Lambda: {func_name}")

        except Exception as e:
            logger.error(f"Failed to deploy Lambda {func_name}: {e}")
            STATS['resources_failed'] += 1

# =============================================================================
# CloudWatch Agent Configuration
# =============================================================================

def store_agent_config():
    cw_config = {
        "agent": {
            "metrics_collection_interval": 60,
            "run_as_user": "root"
        },
        "metrics": {
            "append_dimensions": {
                "InstanceId": "${aws:InstanceId}",
                "InstanceType": "${aws:InstanceType}"
            },
            "metrics_collected": {
                "mem": {"measurement": ["mem_used_percent"], "metrics_collection_interval": 60},
                "disk": {
                    "measurement": ["used_percent", "inodes_free", "inodes_used", "inodes_total"],
                    "metrics_collection_interval": 60,
                    "resources": ["/"]
                },
                "swap": {"measurement": ["swap_used_percent"], "metrics_collection_interval": 60},
                "net": {"measurement": ["bytes_sent", "bytes_recv"], "metrics_collection_interval": 60}
            }
        }
    }
    
    param_name = "AmazonCloudWatch-StandardConfig"
    
    if require_approval(
        action="PutParameter",
        service="SSM",
        resource=param_name,
        params={"Name": param_name},
        reason="Stores the OS-level metric collection configuration for the CW Agent (Memory, Disk, Inodes, Swap, Network)."
    ):
        try:
            ssm = get_boto_client('ssm')
            ssm.put_parameter(
                Name=param_name,
                Description="Standard CloudWatch Agent Configuration",
                Value=json.dumps(cw_config),
                Type="String",
                Overwrite=True
            )
            STATS['resources_created'] += 1
            return param_name
        except Exception as e:
            logger.error(f"Failed to store CW Config: {e}")
    return ""

def deploy_cw_agent():
    print("\n--- Deploying CloudWatch Agent via SSM ---")
    ssm = get_boto_client('ssm')
    
    # Refresh SSM inventory because instances might have just been given SSM roles and are now registering
    fresh_ssm_instances = []
    try:
        for page in ssm.get_paginator('describe_instance_information').paginate():
            for inst in page.get('InstanceInformationList', []):
                fresh_ssm_instances.append(inst['InstanceId'])
    except Exception as e:
        logger.error(f"Failed to refresh SSM instances: {e}")
        
    if not fresh_ssm_instances:
        logger.warning("No SSM managed instances found. CloudWatch Agent cannot be automatically deployed. (Wait 5 mins if you just attached roles)")
        return
        
    INVENTORY['ssm_instances'] = fresh_ssm_instances
    ssm_instances = fresh_ssm_instances
        
    param_name = store_agent_config()
    if not param_name:
        return
        
    ssm = get_boto_client('ssm')
    
    if require_approval(
        action="SendCommand",
        service="SSM",
        resource="AWS-ConfigureAWSPackage",
        params={"Targets": len(ssm_instances)},
        reason="Installs AmazonCloudWatchAgent on all managed EC2 instances."
    ):
        try:
            ssm.send_command(
                Targets=[{"Key": "InstanceIds", "Values": ssm_instances}],
                DocumentName="AWS-ConfigureAWSPackage",
                Parameters={"action": ["Install"], "name": ["AmazonCloudWatchAgent"]}
            )
            logger.info("Triggered CW Agent installation. Waiting 60 seconds for installation to complete...")
            time.sleep(60)
        except Exception as e:
            logger.error(f"Failed to send install command: {e}")

    if require_approval(
        action="SendCommand",
        service="SSM",
        resource="AmazonCloudWatch-ManageAgent",
        params={"Targets": len(ssm_instances)},
        reason="Configures and starts the CloudWatch Agent using the parameter store JSON."
    ):
        try:
            ssm.send_command(
                Targets=[{"Key": "InstanceIds", "Values": ssm_instances}],
                DocumentName="AmazonCloudWatch-ManageAgent",
                Parameters={
                    "action": ["configure"],
                    "mode": ["ec2"],
                    "optionalConfigurationSource": ["ssm"],
                    "optionalConfigurationLocation": [param_name],
                    "optionalRestart": ["yes"]
                }
            )
            logger.info("Triggered CW Agent configuration and startup. Waiting 15 seconds for agent to restart...")
            time.sleep(15)
        except Exception as e:
            logger.error(f"Failed to send config command: {e}")

# =============================================================================
# Alarm Orchestration
# =============================================================================

def create_alarm(sns_topic_arn, alarm_name, metric, namespace,
                 dimensions, threshold, description,
                 operator="GreaterThanThreshold", period=300, eval_periods=2,
                 treat_missing="missing"):
    cw = get_boto_client('cloudwatch')

    if alarm_name in INVENTORY['alarms']:
        action = confirm_existing_resource("CloudWatch Alarm", alarm_name)
        if action == 'SKIP':
            logger.info(f"Skipping existing Alarm: {alarm_name}")
            STATS['resources_skipped'] += 1
            return
        elif action == 'KEEP':
            logger.info(f"Keeping existing Alarm (no action): {alarm_name}")
            return

    if require_approval(
        action="PutMetricAlarm",
        service="CloudWatch",
        resource=alarm_name,
        params={"Metric": metric, "Threshold": threshold, "Namespace": namespace},
        reason=description
    ):
        try:
            cw.put_metric_alarm(
                AlarmName=alarm_name,
                AlarmDescription=description,
                ActionsEnabled=True,
                AlarmActions=[sns_topic_arn],
                MetricName=metric,
                Namespace=namespace,
                Statistic="Average",
                Dimensions=dimensions,
                Period=period,
                EvaluationPeriods=eval_periods,
                Threshold=threshold,
                ComparisonOperator=operator,
                TreatMissingData=treat_missing
            )
            STATS['resources_created'] += 1
            logger.info(f"Created Alarm: {alarm_name}")
        except Exception as e:
            logger.error(f"Failed to create Alarm {alarm_name}: {e}")
            STATS['resources_failed'] += 1

def get_metric_dimensions(instance_id, metric_name, instance_type=None):
    """Queries CloudWatch for actual reported dimensions for a given CWAgent metric."""
    cw = get_boto_client('cloudwatch')
    search_dims = [{"Name": "InstanceId", "Value": instance_id}]
    if instance_type:
        search_dims.append({"Name": "InstanceType", "Value": instance_type})
    try:
        res = cw.list_metrics(
            Namespace="CWAgent",
            MetricName=metric_name,
            Dimensions=search_dims
        )
        if res.get('Metrics'):
            return res['Metrics'][0].get('Dimensions', [])
    except Exception as e:
        logger.warning(f"Could not discover metric dimensions for {metric_name} on {instance_id}: {e}")
    # Fallback defaults using known values from diagnosis
    base = [{"Name": "InstanceId", "Value": instance_id}]
    if instance_type:
        base.append({"Name": "InstanceType", "Value": instance_type})
    if metric_name in ("disk_used_percent", "disk_inodes_free", "disk_inodes_used"):
        base += [
            {"Name": "path",   "Value": "/"},
            {"Name": "device", "Value": "nvme0n1p1"},
            {"Name": "fstype", "Value": "ext4"}
        ]
    return base

def configure_ec2_alarms(sns_topic_arn):
    print("\n--- Configuring EC2 Alarms ---")
    if not sns_topic_arn:
        logger.warning("No SNS Topic ARN provided. Skipping EC2 alarms.")
        return
        
    for inst in INVENTORY['ec2']:
        inst_id = inst['Id']
        inst_name = inst['Name']
        
        # CPU
        create_alarm(sns_topic_arn, f"EC2-CPU-{inst_id}", "CPUUtilization", "AWS/EC2", 
                     [{"Name": "InstanceId", "Value": inst_id}], 80.0, 
                     f"CPU > 80% on {inst_name} ({inst_id})")
        
        # Status Check — uses Maximum statistic, breaching on missing data so
        # a fully unreachable instance still triggers the alarm
        status_alarm = f"EC2-StatusCheck-{inst_id}"
        if status_alarm not in INVENTORY['alarms'] or confirm_existing_resource("CloudWatch Alarm", status_alarm) not in ('SKIP', 'KEEP'):
            if require_approval("PutMetricAlarm", "CloudWatch", status_alarm, {"InstanceId": inst_id}, f"Instance Status Check Failed on {inst_name}"):
                try:
                    cw.put_metric_alarm(
                        AlarmName=status_alarm,
                        AlarmDescription=f"Status check failed on {inst_name}",
                        ActionsEnabled=True,
                        AlarmActions=[sns_topic_arn],
                        MetricName="StatusCheckFailed",
                        Namespace="AWS/EC2",
                        Statistic="Maximum",
                        Dimensions=[{"Name": "InstanceId", "Value": inst_id}],
                        Period=300,
                        EvaluationPeriods=1,
                        Threshold=1.0,
                        ComparisonOperator="GreaterThanOrEqualToThreshold",
                        TreatMissingData="breaching"
                    )
                    STATS['resources_created'] += 1
                    logger.info(f"Created Alarm: {status_alarm}")
                except Exception as e:
                    logger.error(f"Failed to create status check alarm for {inst_id}: {e}")

        # Network Out
        create_alarm(sns_topic_arn, f"EC2-NetworkOut-{inst_id}", "NetworkOut", "AWS/EC2",
                     [{"Name": "InstanceId", "Value": inst_id}], 100000000.0,
                     f"High network traffic (> 100MB/s) outbound on {inst_name}")

        # Memory, Swap, Disk, Inodes alarms — always created, activate once CW Agent starts
        inst_type = inst.get('Type', 'unknown')

        # Memory — CWAgent metric: breaching so agent crash is also caught
        create_alarm(sns_topic_arn, f"EC2-Memory-{inst_id}", "mem_used_percent", "CWAgent",
                     [
                         {"Name": "InstanceId",   "Value": inst_id},
                         {"Name": "InstanceType", "Value": inst_type}
                     ], 85.0, f"Memory Utilization > 85% on {inst_name}",
                     treat_missing="breaching")

        # Swap — CWAgent metric: breaching
        create_alarm(sns_topic_arn, f"EC2-Swap-{inst_id}", "swap_used_percent", "CWAgent",
                     [
                         {"Name": "InstanceId",   "Value": inst_id},
                         {"Name": "InstanceType", "Value": inst_type}
                     ], 50.0, f"Swap Utilization > 50% on {inst_name}",
                     treat_missing="breaching")

        # Disk — correct metric name is disk_used_percent; breaching
        disk_dims = get_metric_dimensions(inst_id, "disk_used_percent", inst_type)
        create_alarm(sns_topic_arn, f"EC2-DiskUsed-{inst_id}", "disk_used_percent", "CWAgent",
                     disk_dims, 60.0, f"Disk Space > 60% on {inst_name}",
                     treat_missing="breaching")

        # Inodes — alerts when free inodes drop too low; breaching
        inode_dims = get_metric_dimensions(inst_id, "disk_inodes_free", inst_type)
        create_alarm(sns_topic_arn, f"EC2-DiskInodes-{inst_id}", "disk_inodes_free", "CWAgent",
                     inode_dims, 1000000.0, f"Disk Inodes critically low on {inst_name}",
                     operator="LessThanThreshold", treat_missing="breaching")

def configure_rds_alarms(sns_topic_arn):
    print("\n--- Configuring RDS Alarms ---")
    if not sns_topic_arn:
        return
        
    for db in INVENTORY['rds']:
        db_id = db['Id']
        create_alarm(sns_topic_arn, f"RDS-CPU-{db_id}", "CPUUtilization", "AWS/RDS", 
                     [{"Name": "DBInstanceIdentifier", "Value": db_id}], 85.0, 
                     f"CPU > 85% on RDS {db_id}")
        
        create_alarm(sns_topic_arn, f"RDS-StorageLow-{db_id}", "FreeStorageSpace", "AWS/RDS", 
                     [{"Name": "DBInstanceIdentifier", "Value": db_id}], 5000000000.0, 
                     f"Free Storage < 5GB on RDS {db_id}", operator="LessThanThreshold")

# =============================================================================
# Web & Database Monitors
# =============================================================================

def detect_web_services(instance_id):
    ssm = get_boto_client('ssm')
    detected = []
    linux_cmd = "pgrep nginx && echo 'nginx' || true; pgrep httpd && echo 'apache' || true; pgrep apache2 && echo 'apache' || true; pgrep -f 'PM2' && echo 'pm2' || true;"
    win_cmd = "if (Get-Process -Name w3wp -ErrorAction SilentlyContinue) { Write-Host 'iis' }"
    
    platform = "Linux"
    try:
        info = ssm.describe_instance_information(Filters=[{"Key": "InstanceIds", "Values": [instance_id]}])
        if info.get('InstanceInformationList'):
            platform = info['InstanceInformationList'][0].get('PlatformType', 'Linux')
    except Exception as e:
        logger.warning(f"Could not get platform info for {instance_id}: {e}")
        
    doc_name = "AWS-RunShellScript" if platform != "Windows" else "AWS-RunPowerShellScript"
    cmd_str = linux_cmd if platform != "Windows" else win_cmd
    
    if require_approval(
        action="SendCommand",
        service="SSM",
        resource=instance_id,
        params={"DocumentName": doc_name, "Command": cmd_str},
        reason=f"Detects whether instance {instance_id} is running Apache, Nginx, or IIS."
    ):
        try:
            res = ssm.send_command(InstanceIds=[instance_id], DocumentName=doc_name, Parameters={"commands": [cmd_str]})
            cmd_id = res['Command']['CommandId']
            
            time.sleep(3)
            for _ in range(6):
                try:
                    invocation = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
                    status = invocation.get('Status', '')
                    if status in ['Success', 'Failed']:
                        output = invocation.get('StandardOutputContent', '').lower()
                        if 'nginx' in output:
                            detected.append('nginx')
                        if 'apache' in output:
                            detected.append('apache')
                        if 'iis' in output:
                            detected.append('iis')
                        if 'pm2' in output:
                            detected.append('pm2')
                        break
                except ssm.exceptions.InvocationDoesNotExist:
                    pass
                time.sleep(2)
        except Exception as e:
            logger.error(f"Failed service detection command on {instance_id}: {e}")
            
    return detected

def restart_web_service(instance_id, service_name):
    ssm = get_boto_client('ssm')
    commands = {
        "nginx": "systemctl restart nginx",
        "apache": "systemctl restart httpd || systemctl restart apache2",
        "iis": "iisreset /restart"
    }
    cmd_str = commands.get(service_name)
    if not cmd_str:
        return
        
    platform = "Linux"
    try:
        info = ssm.describe_instance_information(Filters=[{"Key": "InstanceIds", "Values": [instance_id]}])
        if info.get('InstanceInformationList'):
            platform = info['InstanceInformationList'][0].get('PlatformType', 'Linux')
    except Exception as e:
        logger.warning(f"Could not get platform info for restart on {instance_id}: {e}")
        
    doc_name = "AWS-RunShellScript" if platform != "Windows" else "AWS-RunPowerShellScript"
    
    if require_approval(
        action="SendCommand",
        service="SSM",
        resource=instance_id,
        params={"Command": cmd_str},
        reason=f"Restarts web service '{service_name}' on {instance_id} to restore operational state."
    ):
        try:
            ssm.send_command(InstanceIds=[instance_id], DocumentName=doc_name, Parameters={"commands": [cmd_str]})
            logger.info(f"Triggered restart command for {service_name} on {instance_id}")
        except Exception as e:
            logger.error(f"Failed to send restart command: {e}")

def configure_web_monitoring():
    print("\n--- Configuring Web Server Monitoring ---")
    ssm_instances = INVENTORY['ssm_instances']
    if not ssm_instances:
        logger.warning("No SSM instances available. Skipping web server detection.")
        return

    ssm = get_boto_client('ssm')
    cw = get_boto_client('cloudwatch')
    
    for inst_id in ssm_instances:
        web_services = detect_web_services(inst_id)
        if not web_services:
            continue
            
        logger.info(f"Detected web servers on {inst_id}: {web_services}")
        procstat_config = []
        for service in web_services:
            if service == "pm2":
                # PM2 runs as a Node.js daemon — must use pattern matching, not exe
                procstat_config.append({
                    "pattern": "PM2",
                    "measurement": ["cpu_usage", "memory_rss", "pid_count"]
                })
            else:
                exe_name = "nginx" if service == "nginx" else ("httpd" if service == "apache" else "w3wp")
                procstat_config.append({
                    "exe": exe_name,
                    "measurement": ["cpu_usage", "memory_rss", "pid_count"]
                })
            
        param_name = f"AmazonCloudWatch-WebConfig-{inst_id}"
        cw_config = {
            "metrics": {
                "append_dimensions": {
                    "InstanceId":   "${aws:InstanceId}",
                    "InstanceType": "${aws:InstanceType}"
                },
                "metrics_collected": {"procstat": procstat_config}
            }
        }
        
        if require_approval(
            action="PutParameter",
            service="SSM",
            resource=param_name,
            params={"Name": param_name},
            reason=f"Stores the Web Server (procstat) CW Agent configuration for instance {inst_id}."
        ):
            try:
                ssm.put_parameter(
                    Name=param_name,
                    Description=f"Web Server CloudWatch Agent Configuration for {inst_id}",
                    Value=json.dumps(cw_config),
                    Type="String",
                    Overwrite=True
                )
                
                if require_approval(
                    action="SendCommand", 
                    service="SSM", 
                    resource=f"AmazonCloudWatch-ManageAgent-{inst_id}", 
                    params={"InstanceId": inst_id}, 
                    reason=f"Appends web server monitoring config to instance {inst_id}."
                ):
                    ssm.send_command(
                        InstanceIds=[inst_id],
                        DocumentName="AmazonCloudWatch-ManageAgent",
                        Parameters={
                            "action": ["configure (append)"],
                            "mode": ["ec2"],
                            "optionalConfigurationSource": ["ssm"],
                            "optionalConfigurationLocation": [param_name],
                            "optionalRestart": ["yes"]
                        }
                    )
                    logger.info(f"Triggered CW Agent web server monitoring update for {inst_id}. Waiting 15 seconds...")
                    time.sleep(15)
                    STATS['resources_created'] += 1
                    
                    for service in web_services:
                        alarm_name = f"Web-ProcessDown-{inst_id}-{service}"
                        inst_type = INVENTORY['ec2'][next((i for i, x in enumerate(INVENTORY['ec2']) if x['Id'] == inst_id), 0)].get('Type', 'unknown')

                        # PM2 uses 'pattern' dimension; all others use 'exe' dimension
                        if service == "pm2":
                            process_dims = [
                                {"Name": "InstanceId",   "Value": inst_id},
                                {"Name": "InstanceType", "Value": inst_type},
                                {"Name": "pattern",      "Value": "PM2"},
                                {"Name": "pid_finder",   "Value": "native"}
                            ]
                        else:
                            exe_name = "nginx" if service == "nginx" else ("httpd" if service == "apache" else "w3wp")
                            process_dims = [
                                {"Name": "InstanceId",   "Value": inst_id},
                                {"Name": "InstanceType", "Value": inst_type},
                                {"Name": "exe",          "Value": exe_name},
                                {"Name": "pid_finder",   "Value": "native"}
                            ]

                        if require_approval(
                            action="PutMetricAlarm",
                            service="CloudWatch",
                            resource=alarm_name,
                            params={"MetricName": "procstat_lookup_pid_count", "Threshold": 1.0},
                            reason=f"Alerts when the {service} process count drops below 1 on {inst_id}."
                        ):
                            sns_arn = next((arn for arn in INVENTORY['sns'] if DEFAULT_SNS_TOPIC_NAME in arn), None)
                            if sns_arn:
                                cw.put_metric_alarm(
                                    AlarmName=alarm_name,
                                    AlarmDescription=f"Web Process {service} is down on {inst_id}",
                                    ActionsEnabled=True,
                                    AlarmActions=[sns_arn],
                                    MetricName="procstat_lookup_pid_count",
                                    Namespace="CWAgent",
                                    Statistic="Average",
                                    Dimensions=process_dims,
                                    Period=60,
                                    EvaluationPeriods=1,
                                    Threshold=1.0,
                                    ComparisonOperator="LessThanThreshold",
                                    TreatMissingData="breaching"
                                )
                                logger.info(f"Created alarm {alarm_name}")
                                STATS['resources_created'] += 1

                                # Auto restart query (only for supported web services, not pm2)
                                if service != "pm2":
                                    try:
                                        if AUTO_APPROVE:
                                            restart_choice = 'N'
                                        else:
                                            restart_choice = input(f"Would you like to auto-restart {service} on {inst_id} if detected as down? [Y] Yes | [N] No : ").strip().upper()
                                    except EOFError:
                                        restart_choice = 'N'
                                    if restart_choice == 'Y':
                                        restart_web_service(inst_id, service)
                                    
            except Exception as e:
                logger.error(f"Failed to configure Web monitoring on {inst_id}: {e}")

def detect_db_services(instance_id):
    ssm = get_boto_client('ssm')
    detected = []
    linux_cmd = (
        "pgrep mysqld && echo 'mysql' || true; "
        "pgrep postgres && echo 'postgres' || true; "
        "pgrep sqlservr && echo 'sqlserver' || true; "
        "pgrep oracle && echo 'oracle' || true; "
        "pgrep mongod && echo 'mongodb' || true; "
        "pgrep redis-server && echo 'redis' || true;"
    )
    win_cmd = (
        "if (Get-Process -Name mysqld -ErrorAction SilentlyContinue) { Write-Host 'mysql' }; "
        "if (Get-Process -Name postgres -ErrorAction SilentlyContinue) { Write-Host 'postgres' }; "
        "if (Get-Process -Name sqlservr -ErrorAction SilentlyContinue) { Write-Host 'sqlserver' }; "
        "if (Get-Process -Name mongod -ErrorAction SilentlyContinue) { Write-Host 'mongodb' }; "
        "if (Get-Process -Name redis-server -ErrorAction SilentlyContinue) { Write-Host 'redis' }"
    )
    
    platform = "Linux"
    try:
        info = ssm.describe_instance_information(Filters=[{"Key": "InstanceIds", "Values": [instance_id]}])
        if info.get('InstanceInformationList'):
            platform = info['InstanceInformationList'][0].get('PlatformType', 'Linux')
    except Exception as e:
        logger.warning(f"Could not get platform info for DB detection on {instance_id}: {e}")
        
    doc_name = "AWS-RunShellScript" if platform != "Windows" else "AWS-RunPowerShellScript"
    cmd_str = linux_cmd if platform != "Windows" else win_cmd
    
    if require_approval(
        action="SendCommand",
        service="SSM",
        resource=instance_id,
        params={"DocumentName": doc_name, "Command": cmd_str},
        reason=f"Detects whether instance {instance_id} is running MySQL, PostgreSQL, SQL Server, Oracle, MongoDB, or Redis."
    ):
        try:
            res = ssm.send_command(InstanceIds=[instance_id], DocumentName=doc_name, Parameters={"commands": [cmd_str]})
            cmd_id = res['Command']['CommandId']
            
            time.sleep(3)
            for _ in range(6):
                try:
                    invocation = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
                    status = invocation.get('Status', '')
                    if status in ['Success', 'Failed']:
                        output = invocation.get('StandardOutputContent', '').lower()
                        for db in ['mysql', 'postgres', 'sqlserver', 'oracle', 'mongodb', 'redis']:
                            if db in output:
                                detected.append(db)
                        break
                except ssm.exceptions.InvocationDoesNotExist:
                    pass
                time.sleep(2)
        except Exception as e:
            logger.error(f"Failed service detection command on {instance_id}: {e}")
            
    return detected

def configure_rds_engine_alarms(sns_topic_arn):
    cw = get_boto_client('cloudwatch')
    for db in INVENTORY['rds']:
        db_id = db['Id']
        engine = db['Engine'].lower()
        
        alarm_name = f"RDS-Connections-{db_id}"
        if require_approval(
            action="PutMetricAlarm",
            service="CloudWatch",
            resource=alarm_name,
            params={"DBInstanceIdentifier": db_id, "Metric": "DatabaseConnections", "Threshold": 150},
            reason=f"Alerts when database connection count exceeds 150 on RDS {db_id}."
        ):
            try:
                cw.put_metric_alarm(
                    AlarmName=alarm_name,
                    AlarmDescription=f"High database connections on RDS {db_id}",
                    ActionsEnabled=True,
                    AlarmActions=[sns_topic_arn],
                    MetricName="DatabaseConnections",
                    Namespace="AWS/RDS",
                    Statistic="Maximum",
                    Dimensions=[{"Name": "DBInstanceIdentifier", "Value": db_id}],
                    Period=300,
                    EvaluationPeriods=2,
                    Threshold=150.0,
                    ComparisonOperator="GreaterThanThreshold"
                )
                logger.info(f"Created Connections Alarm for RDS {db_id}")
                STATS['resources_created'] += 1
            except Exception as e:
                logger.error(f"Failed to create Connections Alarm for RDS {db_id}: {e}")
                STATS['resources_failed'] += 1

        if 'postgres' in engine:
            repl_alarm = f"RDS-ReplicationLag-{db_id}"
            if require_approval(
                action="PutMetricAlarm",
                service="CloudWatch",
                resource=repl_alarm,
                params={"Metric": "ReplicationLag", "Threshold": 60.0},
                reason=f"Alerts when replication lag exceeds 60 seconds on PostgreSQL RDS {db_id}."
            ):
                try:
                    cw.put_metric_alarm(
                        AlarmName=repl_alarm,
                        AlarmDescription=f"High replication lag on RDS {db_id}",
                        ActionsEnabled=True,
                        AlarmActions=[sns_topic_arn],
                        MetricName="ReplicationLag",
                        Namespace="AWS/RDS",
                        Statistic="Average",
                        Dimensions=[{"Name": "DBInstanceIdentifier", "Value": db_id}],
                        Period=300,
                        EvaluationPeriods=2,
                        Threshold=60.0,
                        ComparisonOperator="GreaterThanThreshold"
                    )
                    logger.info(f"Created ReplicationLag Alarm for PostgreSQL RDS {db_id}")
                    STATS['resources_created'] += 1
                except Exception as e:
                    logger.error(f"Failed to create ReplicationLag Alarm: {e}")

def configure_database_monitoring():
    print("\n--- Configuring Database Monitoring ---")
    sns_arn = next((arn for arn in INVENTORY['sns'] if DEFAULT_SNS_TOPIC_NAME in arn), None)
    if sns_arn and INVENTORY['rds']:
        configure_rds_engine_alarms(sns_arn)
        
    ssm_instances = INVENTORY['ssm_instances']
    if not ssm_instances:
        logger.warning("No SSM instances available. Skipping self-managed DB detection.")
        return

    ssm = get_boto_client('ssm')
    cw = get_boto_client('cloudwatch')
    
    for inst_id in ssm_instances:
        db_engines = detect_db_services(inst_id)
        if not db_engines:
            continue
            
        logger.info(f"Detected database engines on {inst_id}: {db_engines}")
        procstat_config = []
        for engine in db_engines:
            exe_map = {
                "mysql": "mysqld",
                "postgres": "postgres",
                "sqlserver": "sqlservr",
                "oracle": "oracle",
                "mongodb": "mongod",
                "redis": "redis-server"
            }
            exe_name = exe_map.get(engine, "mysqld")
            procstat_config.append({
                "exe": exe_name,
                "measurement": ["cpu_usage", "memory_rss", "pid_count"]
            })
            
        param_name = f"AmazonCloudWatch-DBConfig-{inst_id}"
        cw_config = {
            "metrics": {
                "append_dimensions": {
                    "InstanceId":   "${aws:InstanceId}",
                    "InstanceType": "${aws:InstanceType}"
                },
                "metrics_collected": {"procstat": procstat_config}
            }
        }
        
        if require_approval(
            action="PutParameter",
            service="SSM",
            resource=param_name,
            params={"Name": param_name},
            reason=f"Stores the Database Server (procstat) CW Agent configuration for instance {inst_id}."
        ):
            try:
                ssm.put_parameter(
                    Name=param_name,
                    Description=f"Database CloudWatch Agent Configuration for {inst_id}",
                    Value=json.dumps(cw_config),
                    Type="String",
                    Overwrite=True
                )
                
                if require_approval(
                    action="SendCommand",
                    service="SSM",
                    resource=f"AmazonCloudWatch-ManageAgent-DB-{inst_id}",
                    params={"InstanceId": inst_id},
                    reason=f"Appends database monitoring config to instance {inst_id}."
                ):
                    ssm.send_command(
                        InstanceIds=[inst_id],
                        DocumentName="AmazonCloudWatch-ManageAgent",
                        Parameters={
                            "action": ["configure (append)"],
                            "mode": ["ec2"],
                            "optionalConfigurationSource": ["ssm"],
                            "optionalConfigurationLocation": [param_name],
                            "optionalRestart": ["yes"]
                        }
                    )
                    logger.info(f"Triggered CW Agent database monitoring update for {inst_id}. Waiting 15 seconds...")
                    time.sleep(15)
                    STATS['resources_created'] += 1
                    
                    for engine in db_engines:
                        exe_map = {
                            "mysql": "mysqld",
                            "postgres": "postgres",
                            "sqlserver": "sqlservr",
                            "oracle": "oracle",
                            "mongodb": "mongod",
                            "redis": "redis-server"
                        }
                        exe_name = exe_map.get(engine, "mysqld")
                        alarm_name = f"DB-ProcessDown-{inst_id}-{engine}"
                        
                        if require_approval(
                            action="PutMetricAlarm",
                            service="CloudWatch",
                            resource=alarm_name,
                            params={"MetricName": "procstat_lookup_pid_count", "Threshold": 1.0},
                            reason=f"Alerts when self-managed DB engine '{engine}' is down on {inst_id}."
                        ):
                            if sns_arn:
                                cw.put_metric_alarm(
                                    AlarmName=alarm_name,
                                    AlarmDescription=f"Database process {engine} is down on {inst_id}",
                                    ActionsEnabled=True,
                                    AlarmActions=[sns_arn],
                                    MetricName="procstat_lookup_pid_count",
                                    Namespace="CWAgent",
                                    Statistic="Average",
                                    Dimensions=[
                                        {"Name": "InstanceId",   "Value": inst_id},
                                        {"Name": "InstanceType", "Value": INVENTORY['ec2'][next((i for i, x in enumerate(INVENTORY['ec2']) if x['Id'] == inst_id), 0)].get('Type', 'unknown')},
                                        {"Name": "exe",          "Value": exe_name},
                                        {"Name": "pid_finder",   "Value": "native"}
                                    ],
                                    Period=60,
                                    EvaluationPeriods=1,
                                    Threshold=1.0,
                                    ComparisonOperator="LessThanThreshold",
                                    TreatMissingData="breaching"
                                )
                                logger.info(f"Created alarm {alarm_name}")
                                STATS['resources_created'] += 1
                                
            except Exception as e:
                logger.error(f"Failed to configure database monitoring on {inst_id}: {e}")

# =============================================================================
# SSL & Application Canaries
# =============================================================================

SSL_CHECKER_CODE = """
import ssl
import socket
import datetime
import json
import boto3
import os

def check_ssl_expiry(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_str = cert.get('notAfter')
                expiry_date = datetime.datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=datetime.timezone.utc)
                days_remaining = (expiry_date - datetime.datetime.now(datetime.timezone.utc)).days
                return days_remaining
    except Exception as e:
        print(f"Error checking {domain}: {e}")
        return -1

def lambda_handler(event, context):
    domains_str = os.environ.get('DOMAINS', '')
    if not domains_str:
        return {"statusCode": 200, "body": "No domains configured"}
        
    sns_arn = os.environ.get('SNS_TOPIC_ARN')
    sns = boto3.client('sns')
    
    domains = domains_str.split(',')
    for domain in domains:
        domain = domain.strip()
        if not domain: continue
        
        days = check_ssl_expiry(domain)
        if days == -1:
            if sns_arn:
                sns.publish(
                    TopicArn=sns_arn,
                    Subject="SSL Check Failed",
                    Message=json.dumps({"AlarmName": f"SSL-Check-{domain}", "NewStateValue": "ALARM", "NewStateReason": f"Could not connect to check SSL for {domain}"})
                )
            continue
            
        if days <= 30:
            msg = f"SSL Certificate for {domain} expires in {days} days!" if days > 0 else f"SSL Certificate for {domain} has EXPIRED!"
            if sns_arn:
                sns.publish(
                    TopicArn=sns_arn,
                    Subject=f"SSL Expiry Alert: {domain}",
                    Message=json.dumps({"AlarmName": f"SSL-Expiry-{domain}", "NewStateValue": "ALARM", "NewStateReason": msg})
                )
                
    return {"statusCode": 200, "body": "Checked"}
"""

def configure_acm_alarms(sns_topic_arn):
    cw = get_boto_client('cloudwatch')
    logger.info("Configuring ACM Certificate Expiry Alarms...")
    for cert in INVENTORY['acm_certs']:
        cert_arn = cert['Arn']
        domain_name = cert['DomainName']
        alarm_name = f"ACM-Expiry-{domain_name}"
        
        if require_approval(
            action="PutMetricAlarm",
            service="CloudWatch",
            resource=alarm_name,
            params={"CertificateArn": cert_arn, "Threshold": 30.0},
            reason=f"Alerts when ACM Certificate for {domain_name} has <= 30 days remaining."
        ):
            try:
                cw.put_metric_alarm(
                    AlarmName=alarm_name,
                    AlarmDescription=f"ACM certificate for {domain_name} is expiring soon.",
                    ActionsEnabled=True,
                    AlarmActions=[sns_topic_arn],
                    MetricName="DaysToExpiry",
                    Namespace="AWS/CertificateManager",
                    Statistic="Minimum",
                    Dimensions=[{"Name": "CertificateArn", "Value": cert_arn}],
                    Period=86400,
                    EvaluationPeriods=1,
                    Threshold=30.0,
                    ComparisonOperator="LessThanOrEqualToThreshold"
                )
                logger.info(f"Created ACM Alarm for {domain_name}")
                STATS['resources_created'] += 1
            except Exception as e:
                logger.error(f"Failed to create ACM Alarm for {domain_name}: {e}")
                STATS['resources_failed'] += 1

def configure_ssl_monitor(role_arn, sns_topic_arn):
    print("\n--- Configuring External SSL Monitoring ---")
    if sns_topic_arn and INVENTORY['acm_certs']:
        configure_acm_alarms(sns_topic_arn)
        
    if DRY_RUN:
        return
        
    domains = get_input("Enter external domains to monitor for SSL expiry (comma-separated, blank to skip): ", "SSL_DOMAINS")
        
    if not domains:
        return
        
    if not role_arn:
        logger.warning("No IAM Role available. Cannot deploy SSL Checker Lambda.")
        return
        
    lmb = get_boto_client('lambda')
    events = get_boto_client('events')
    func_name = "AWSMonitoringSSLChecker"
    
    if require_approval(
        action="CreateFunction",
        service="Lambda",
        resource=func_name,
        params={"Domains": domains},
        reason="Deploys a Lambda to check external SSL certs daily and alert via SNS."
    ):
        zip_bytes = create_lambda_zip(SSL_CHECKER_CODE)
        
        try:
            try:
                lmb.update_function_code(FunctionName=func_name, ZipFile=zip_bytes)
                lmb.update_function_configuration(
                    FunctionName=func_name,
                    Environment={'Variables': {'DOMAINS': domains, 'SNS_TOPIC_ARN': sns_topic_arn}}
                )
                func_arn = lmb.get_function(FunctionName=func_name)['Configuration']['FunctionArn']
                logger.info(f"Updated SSL Checker Lambda: {func_name}")
            except lmb.exceptions.ResourceNotFoundException:
                retries = 6
                while retries > 0:
                    try:
                        res = lmb.create_function(
                            FunctionName=func_name,
                            Runtime='python3.11',
                            Role=role_arn,
                            Handler='index.lambda_handler',
                            Code={'ZipFile': zip_bytes},
                            Environment={'Variables': {'DOMAINS': domains, 'SNS_TOPIC_ARN': sns_topic_arn}},
                            Timeout=60
                        )
                        func_arn = res['FunctionArn']
                        STATS['resources_created'] += 1
                        break
                    except ClientError as e:
                        if e.response.get('Error', {}).get('Code') == 'InvalidParameterValueException' and 'cannot be assumed' in e.response.get('Error', {}).get('Message', ''):
                            logger.warning("IAM role is still propagating. Retrying in 5 seconds...")
                            time.sleep(5)
                            retries -= 1
                        else:
                            raise e
                else:
                    raise Exception("Failed to deploy SSL Checker Lambda: IAM role propagation timed out.")
                
            # Create EventBridge trigger (daily check)
            rule_name = f"{func_name}-DailyTrigger"
            if require_approval("PutRule", "EventBridge", rule_name, {"Schedule": "rate(1 day)"}, "Triggers SSL checks daily."):
                events.put_rule(Name=rule_name, ScheduleExpression="rate(1 day)", State='ENABLED')
                events.put_targets(Rule=rule_name, Targets=[{'Id': 'SSLCheckerTarget', 'Arn': func_arn}])
                
                try:
                    lmb.add_permission(
                        FunctionName=func_name,
                        StatementId="events-invoke",
                        Action="lambda:InvokeFunction",
                        Principal="events.amazonaws.com",
                        SourceArn=f"arn:aws:events:{AWS_REGION}:{AWS_ACCOUNT_ID}:rule/{rule_name}"
                    )
                except lmb.exceptions.ResourceConflictException:
                    pass

        except Exception as e:
            logger.error(f"Failed to deploy SSL Checker Lambda: {e}")
            STATS['resources_failed'] += 1

SYNTHETICS_CODE = """
const synthetics = require('Synthetics');
const log = require('SyntheticsLogger');

const pageLoadBlueprint = async function () {
    const URL = process.env.URL;
    let page = await synthetics.getPage();
    let response = await page.goto(URL, {waitUntil: 'domcontentloaded', timeout: 30000});
    
    if (!response) {
        throw "Failed to load page!";
    }
    
    if (response.status() !== 200) {
        throw "Failed to load page! Status code: " + response.status();
    }
    
    log.info("Page loaded successfully.");
};

exports.handler = async () => {
    return await pageLoadBlueprint();
};
"""

def create_lambda_zip(code_string):
    """Creates an in-memory ZIP file containing a Python Lambda function."""
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('index.py', code_string)
    return zip_buffer.getvalue()

def create_synthetics_zip():
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('nodejs/node_modules/pageLoadBlueprint.js', SYNTHETICS_CODE)
    return zip_buffer.getvalue()

def configure_application_monitoring(role_arn, sns_topic_arn):
    print("\n--- Configuring Application Monitoring ---")
    if DRY_RUN:
        return
        
    urls = get_input("Enter Application Health URLs to monitor (comma-separated, blank to skip): ", "HEALTH_URLS")
        
    if not urls:
        return
        
    if not role_arn:
        logger.warning("No IAM Role available for Synthetics Canaries.")
        return
        
    synthetics = get_boto_client('synthetics')
    cw = get_boto_client('cloudwatch')
    s3 = get_boto_client('s3')
    
    bucket_name = f"cw-synthetics-artifacts-{AWS_ACCOUNT_ID}-{AWS_REGION}"
    try:
        s3.head_bucket(Bucket=bucket_name)
    except ClientError:
        if require_approval("CreateBucket", "S3", bucket_name, {}, "Required for CloudWatch Synthetics Artifacts."):
            try:
                if AWS_REGION == 'us-east-1':
                    s3.create_bucket(Bucket=bucket_name)
                else:
                    s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={'LocationConstraint': AWS_REGION})
            except Exception as e:
                logger.error(f"Failed to create S3 bucket: {e}")
                return
                
    zip_bytes = create_synthetics_zip()
    
    for idx, url in enumerate(urls.split(',')):
        url = url.strip()
        if not url: continue
        
        canary_name = f"app-check-{idx}"
        if require_approval(
            action="CreateCanary",
            service="Synthetics",
            resource=canary_name,
            params={"URL": url},
            reason="Deploys a Puppeteer Node.js canary to check application health state."
        ):
            try:
                retries = 6
                while retries > 0:
                    try:
                        synthetics.create_canary(
                            Name=canary_name,
                            Code={'ZipFile': zip_bytes, 'Handler': 'pageLoadBlueprint.handler'},
                            ArtifactS3Location=f"s3://{bucket_name}/canary/{canary_name}",
                            ExecutionRoleArn=role_arn,
                            Schedule={'Expression': 'rate(5 minutes)'},
                            RunConfig={'EnvironmentVariables': {'URL': url}, 'TimeoutInSeconds': 60},
                            RuntimeVersion='syn-nodejs-puppeteer-7.0'
                        )
                        break
                    except ClientError as e:
                        msg = e.response.get('Error', {}).get('Message', '')
                        if 'cannot be assumed' in msg or 'AssumeRole' in msg or 'role' in msg.lower():
                            logger.warning("IAM role is still propagating for Canary. Retrying in 5 seconds...")
                            time.sleep(5)
                            retries -= 1
                        else:
                            raise e
                else:
                    raise Exception("Failed to create Canary: IAM role propagation timed out.")
                
                time.sleep(5)
                synthetics.start_canary(Name=canary_name)
                STATS['resources_created'] += 1
                
                alarm_name = f"Synthetics-Failed-{canary_name}"
                if require_approval("PutMetricAlarm", "CloudWatch", alarm_name, {"Canary": canary_name}, f"Alerts when canary {canary_name} fails."):
                    cw.put_metric_alarm(
                        AlarmName=alarm_name,
                        AlarmDescription=f"Application Health Check Failed for {url}",
                        ActionsEnabled=True,
                        AlarmActions=[sns_topic_arn],
                        MetricName="Failed",
                        Namespace="CloudWatchSynthetics",
                        Statistic="Sum",
                        Dimensions=[{"Name": "CanaryName", "Value": canary_name}],
                        Period=300,
                        EvaluationPeriods=1,
                        Threshold=1.0,
                        ComparisonOperator="GreaterThanOrEqualToThreshold"
                    )
                    logger.info(f"Deployed Canary & Alarm for {url}")
                    STATS['resources_created'] += 1
            except Exception as e:
                logger.error(f"Failed to create canary for {url}: {e}")
                STATS['resources_failed'] += 1

# =============================================================================
# Account Auditing (EventBridge)
# =============================================================================

def configure_cloudtrail_auditing():
    print("\n--- Configuring Serverless Account Auditing (EventBridge to CloudWatch) ---")
    if DRY_RUN:
        return
        
    logs = get_boto_client('logs')
    events = get_boto_client('events')
    
    log_group_name = "/aws/events/AccountAuditLogs"
    rule_name = "Central-Account-Audit-Rule"
    
    # 1. Create CloudWatch Log Group
    log_group_arn = None
    if require_approval("CreateLogGroup", "CloudWatch Logs", log_group_name, {"RetentionInDays": 365}, "Centralizes API audit logs."):
        try:
            try:
                logs.create_log_group(logGroupName=log_group_name)
                logs.put_retention_policy(logGroupName=log_group_name, retentionInDays=365)
                STATS['resources_created'] += 1
            except logs.exceptions.ResourceAlreadyExistsException:
                pass
            
            res = logs.describe_log_groups(logGroupNamePrefix=log_group_name)
            log_group = next(lg for lg in res['logGroups'] if lg['logGroupName'] == log_group_name)
            log_group_arn = log_group['arn']
            if not log_group_arn.endswith(':*'):
                log_group_arn = f"{log_group_arn}:*"
                
            logger.info(f"Configured Log Group: {log_group_name}")
        except Exception as e:
            logger.error(f"Failed to create Log Group: {e}")
            STATS['resources_failed'] += 1
            return

    # 2. Add Resource Policy to Log Group
    if log_group_arn and require_approval("PutResourcePolicy", "CloudWatch Logs", log_group_name, {}, "Allows EventBridge to write audit events to the log group."):
        try:
            policy_doc = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "events.amazonaws.com"},
                        "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": log_group_arn
                    }
                ]
            }
            logs.put_resource_policy(
                policyName="EventBridgeToCWLogsPolicy",
                policyDocument=json.dumps(policy_doc)
            )
            logger.info("Configured CloudWatch Logs resource policy.")
        except Exception as e:
            logger.error(f"Failed to set Resource Policy: {e}")
            STATS['resources_failed'] += 1
            return

    # 3. Create EventBridge Rule and Target
    if log_group_arn and require_approval("PutRule", "EventBridge", rule_name, {}, "Intercepts all AWS API calls and routes them to CloudWatch."):
        try:
            event_pattern = {
                "source": [{"prefix": "aws."}]
            }
            events.put_rule(
                Name=rule_name,
                EventPattern=json.dumps(event_pattern),
                State='ENABLED',
                Description="Routes AWS API Call events to CloudWatch Logs"
            )
            STATS['resources_created'] += 1
            
            # EventBridge targets require the base log group ARN (without :*)
            base_log_group_arn = log_group_arn[:-2] if log_group_arn.endswith(':*') else log_group_arn
            
            events.put_targets(
                Rule=rule_name,
                Targets=[{
                    'Id': 'AuditLogsTarget',
                    'Arn': base_log_group_arn
                }]
            )
            logger.info(f"Successfully activated Serverless Auditing Rule: {rule_name}")
        except Exception as e:
            logger.error(f"Failed to create EventBridge Rule: {e}")
            STATS['resources_failed'] += 1

# =============================================================================
# Dashboard Builder
# =============================================================================

def generate_dashboard():
    print("\n--- Generating Central Dashboard ---")
    cw = get_boto_client('cloudwatch')
    dash_name = "Infrastructure-Overview"
    
    if dash_name in INVENTORY['dashboards']:
        action = confirm_existing_resource("CloudWatch Dashboard", dash_name)
        if action == 'SKIP':
            logger.info(f"Skipping Dashboard creation for {dash_name}")
            STATS['resources_skipped'] += 1
            return
        elif action == 'KEEP':
            logger.info(f"Keeping existing Dashboard: {dash_name}")
            return
            
    widgets = []
    y_offset = 0
    
    # 1. Alarms Widget
    alarm_arns = [f"arn:aws:cloudwatch:{AWS_REGION}:{AWS_ACCOUNT_ID}:alarm:{a}" for a in INVENTORY['alarms']]
    if alarm_arns:
        widgets.append({
            "type": "alarm",
            "x": 0, "y": y_offset, "width": 24, "height": 4,
            "properties": {"title": "Active Infrastructure Alarms", "alarms": alarm_arns}
        })
        y_offset += 4
        
    # 2. EC2 Compute — Memory uses InstanceId + InstanceType
    ec2_cpu = [["AWS/EC2", "CPUUtilization"]]
    ec2_mem = []
    for inst in INVENTORY['ec2']:
        ec2_cpu.append(["AWS/EC2", "CPUUtilization", "InstanceId", inst['Id'], {"label": inst['Name']}])
        ec2_mem.append(["CWAgent", "mem_used_percent",
                        "InstanceId", inst['Id'],
                        "InstanceType", inst.get('Type', 'unknown'),
                        {"label": inst['Name']}])
        
    widgets.append({
        "type": "metric", "x": 0, "y": y_offset, "width": 12, "height": 6,
        "properties": {"metrics": ec2_cpu, "view": "timeSeries", "stacked": False, "region": AWS_REGION, "title": "EC2 CPU Utilization (%)"}
    })
    widgets.append({
        "type": "metric", "x": 12, "y": y_offset, "width": 12, "height": 6,
        "properties": {"metrics": ec2_mem, "view": "timeSeries", "stacked": False, "region": AWS_REGION, "title": "EC2 Memory Utilization (%)"}
    })
    y_offset += 6

    # 3. Disk Space / Inodes — correct metric names: disk_used_percent, disk_inodes_free
    ec2_disk  = []
    ec2_inode = []
    for inst in INVENTORY['ec2']:
        inst_type = inst.get('Type', 'unknown')
        # Try to get real dims from CloudWatch; fall back to sensible defaults
        disk_dims  = get_metric_dimensions(inst['Id'], "disk_used_percent",        inst_type)
        inode_dims = get_metric_dimensions(inst['Id'], "disk_inodes_free", inst_type)
        disk_entry  = ["CWAgent", "disk_used_percent"]
        inode_entry = ["CWAgent", "disk_inodes_free"]
        for d in disk_dims:
            disk_entry += [d['Name'], d['Value']]
        disk_entry.append({"label": f"{inst['Name']} Disk"})
        for d in inode_dims:
            inode_entry += [d['Name'], d['Value']]
        inode_entry.append({"label": f"{inst['Name']} Inodes"})
        ec2_disk.append(disk_entry)
        ec2_inode.append(inode_entry)
        
    widgets.append({
        "type": "metric", "x": 0, "y": y_offset, "width": 12, "height": 6,
        "properties": {"metrics": ec2_disk, "view": "timeSeries", "stacked": False, "region": AWS_REGION, "title": "EC2 Disk Utilization (%)"}
    })
    widgets.append({
        "type": "metric", "x": 12, "y": y_offset, "width": 12, "height": 6,
        "properties": {"metrics": ec2_inode, "view": "timeSeries", "stacked": False, "region": AWS_REGION, "title": "EC2 Free Inodes (Count)"}
    })
    y_offset += 6

    # 4. Network / RDS / S3
    ec2_net = [["AWS/EC2", "NetworkIn"], ["AWS/EC2", "NetworkOut"]]
    for inst in INVENTORY['ec2']:
        ec2_net.append(["AWS/EC2", "NetworkIn", "InstanceId", inst['Id'], {"label": f"{inst['Name']} In"}])
        ec2_net.append(["AWS/EC2", "NetworkOut", "InstanceId", inst['Id'], {"label": f"{inst['Name']} Out"}])
        
    rds_cpu = [["AWS/RDS", "CPUUtilization"]]
    for db in INVENTORY['rds']:
        rds_cpu.append(["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", db['Id']])
        
    s3_storage = []
    for bucket in INVENTORY.get('s3_buckets', []):
        s3_storage.append(["AWS/S3", "BucketSizeBytes", "StorageType", "StandardStorage", "BucketName", bucket, {"label": bucket}])
    
    if not s3_storage:
        s3_storage = [["AWS/S3", "BucketSizeBytes", "StorageType", "StandardStorage"]]
    
    widgets.append({
        "type": "metric", "x": 0, "y": y_offset, "width": 8, "height": 6,
        "properties": {"metrics": ec2_net, "view": "timeSeries", "stacked": False, "region": AWS_REGION, "title": "EC2 Network Traffic"}
    })
    widgets.append({
        "type": "metric", "x": 8, "y": y_offset, "width": 8, "height": 6,
        "properties": {"metrics": rds_cpu, "view": "timeSeries", "stacked": False, "region": AWS_REGION, "title": "RDS CPU Utilization (%)"}
    })
    widgets.append({
        "type": "metric", "x": 16, "y": y_offset, "width": 8, "height": 6,
        "properties": {"metrics": s3_storage, "view": "timeSeries", "stacked": False, "region": AWS_REGION, "title": "S3 Bucket Sizes (Bytes)"}
    })
    y_offset += 6

    # 5. SSL / Canaries
    acm_metrics = [["AWS/CertificateManager", "DaysToExpiry", "CertificateArn", cert['Arn'], {"label": cert['DomainName']}] for cert in INVENTORY['acm_certs']]
    canary_metrics = [["CloudWatchSynthetics", "SuccessPercent", "CanaryName", a.replace('Synthetics-Failed-', '')] for a in INVENTORY['alarms'] if a.startswith('Synthetics-Failed-')]
    
    if acm_metrics:
        widgets.append({
            "type": "metric", "x": 0, "y": y_offset, "width": 12, "height": 6,
            "properties": {"metrics": acm_metrics, "view": "timeSeries", "stacked": False, "region": AWS_REGION, "title": "ACM Certificate Days to Expiry"}
        })
    if canary_metrics:
        widgets.append({
            "type": "metric", "x": 12, "y": y_offset, "width": 12, "height": 6,
            "properties": {"metrics": canary_metrics, "view": "timeSeries", "stacked": False, "region": AWS_REGION, "title": "Synthetics Canaries Success Rate (%)"}
        })
    if acm_metrics or canary_metrics:
        y_offset += 6

    # 6. Lambda & SNS Health
    lambda_metrics = [
        ["AWS/Lambda", "Errors",       {"stat": "Sum", "label": "Lambda Errors"}],
        ["AWS/Lambda", "Invocations",  {"stat": "Sum", "label": "Lambda Invocations"}]
    ]
    sns_metrics = [
        ["AWS/SNS", "NumberOfMessagesPublished",    {"stat": "Sum", "label": "Messages Published"}],
        ["AWS/SNS", "NumberOfNotificationsFailed",  {"stat": "Sum", "label": "Notifications Failed"}]
    ]
    
    widgets.append({
        "type": "metric", "x": 0, "y": y_offset, "width": 12, "height": 6,
        "properties": {"metrics": lambda_metrics, "view": "timeSeries", "stacked": False, "region": AWS_REGION, "title": "Lambda Operations"}
    })
    widgets.append({
        "type": "metric", "x": 12, "y": y_offset, "width": 12, "height": 6,
        "properties": {"metrics": sns_metrics, "view": "timeSeries", "stacked": False, "region": AWS_REGION, "title": "SNS Operations"}
    })
    y_offset += 6

    # 7. Process Health — shows pid count for Nginx, Apache, PM2, MySQL, etc.
    # Scans INVENTORY alarms for Web-ProcessDown and DB-ProcessDown to auto-build widget entries
    process_metrics = []
    for alarm_name in INVENTORY['alarms']:
        if alarm_name.startswith("Web-ProcessDown-") or alarm_name.startswith("DB-ProcessDown-"):
            parts = alarm_name.split("-")
            # Format: Web-ProcessDown-<inst_id>-<service>  or  DB-ProcessDown-<inst_id>-<engine>
            # inst_id is parts[2], service is parts[3]
            if len(parts) >= 4:
                inst_id  = parts[2]
                service  = parts[3]
                # PM2 uses pattern dimension, others use exe
                if service == "pm2":
                    process_metrics.append([
                        "CWAgent", "procstat_lookup_pid_count",
                        "InstanceId", inst_id,
                        "pattern", "PM2",
                        "pid_finder", "native",
                        {"label": f"{inst_id[:8]} - PM2"}
                    ])
                else:
                    exe_map = {
                        "nginx": "nginx", "apache": "httpd", "iis": "w3wp",
                        "mysql": "mysqld", "postgres": "postgres",
                        "mongodb": "mongod", "redis": "redis-server",
                        "sqlserver": "sqlservr", "oracle": "oracle"
                    }
                    exe_name = exe_map.get(service, service)
                    process_metrics.append([
                        "CWAgent", "procstat_lookup_pid_count",
                        "InstanceId", inst_id,
                        "exe", exe_name,
                        "pid_finder", "native",
                        {"label": f"{inst_id[:8]} - {service}"}
                    ])

    if process_metrics:
        widgets.append({
            "type": "metric", "x": 0, "y": y_offset, "width": 24, "height": 6,
            "properties": {
                "metrics": process_metrics,
                "view": "timeSeries",
                "stacked": False,
                "region": AWS_REGION,
                "title": "Process Health (PID Count — Nginx / Apache / PM2 / MySQL / Redis)"
            }
        })
        y_offset += 6

    if not widgets:
        return
        
    dash_body = json.dumps({"widgets": widgets})
    
    if require_approval(
        action="PutDashboard",
        service="CloudWatch",
        resource=dash_name,
        params={"DashboardName": dash_name},
        reason="Creates the visual dashboard panel overview for all system resources."
    ):
        try:
            cw.put_dashboard(DashboardName=dash_name, DashboardBody=dash_body)
            STATS['resources_created'] += 1
            logger.info(f"Dashboard created: {dash_name}")
        except Exception as e:
            logger.error(f"Failed to create Dashboard: {e}")

# =============================================================================
# Helper Utility
# =============================================================================

def print_banner():
    print("\n" + "="*80)
    print(" AWS INFRASTRUCTURE MONITORING DEPLOYMENT SYSTEM (UNIFIED) ")
    print("="*80)

def print_summary():
    print("\n" + "="*80)
    print(" DEPLOYMENT & MONITORING SUMMARY REPORT ")
    print("="*80)
    print(f"AWS Account ID        : {AWS_ACCOUNT_ID}")
    print(f"Region                : {AWS_REGION}")
    print(f"Administrator         : {ADMIN_IDENTITY}")
    print("-" * 80)
    print(f"EC2 Instances Found   : {len(INVENTORY['ec2'])}")
    print(f"RDS Instances Found   : {len(INVENTORY['rds'])}")
    print(f"VPCs Discovered       : {len(INVENTORY['vpc'])}")
    print("-" * 80)
    print(f"Resources Discovered  : {STATS['resources_discovered']}")
    print(f"Resources Created     : {STATS['resources_created']}")
    print(f"Resources Updated     : {STATS['resources_updated']}")
    print(f"Resources Skipped     : {STATS['resources_skipped']}")
    print(f"Resources Failed      : {STATS['resources_failed']}")
    print("="*80)
    print(f"Details logged to {LOG_FILE}\n")

# =============================================================================
# Main Handler Orchestration
# =============================================================================

def main():
    load_dotenv()
    global DRY_RUN, CLEAN_ALARMS
    
    parser = argparse.ArgumentParser(description="AWS Monitoring Setup")
    parser.add_argument("--dry-run", action="store_true", help="Execute discovery but do not modify AWS resources.")
    parser.add_argument("--clean-alarms", action="store_true", help="Delete all previously created monitoring alarms before deploying.")
    parser.add_argument("--auto-approve", action="store_true", help="Automatically approve all prompts without asking.")
    args = parser.parse_args()

    DRY_RUN = args.dry_run
    CLEAN_ALARMS = args.clean_alarms
    
    global AUTO_APPROVE
    if args.auto_approve:
        AUTO_APPROVE = True

    print_banner()

    if DRY_RUN:
        print("\n>>> RUNNING IN DRY-RUN MODE (No changes will be made) <<<\n")
        logger.info("Started execution in DRY-RUN mode.")

    logger.info("Validating Administrator Identity...")
    validate_identity()

    print("\nPlease verify you have intended to run this deployment.")
    if not AUTO_APPROVE:
        try:
            input("Press ENTER to begin Discovery Phase or Ctrl+C to abort...")
        except EOFError:
            pass

    # Phase 1: Discovery
    logger.info("Starting Phase 1: Discovery")
    run_discovery()

    # Phase 2: Alarm Cleanup
    if CLEAN_ALARMS:
        delete_old_alarms()
    else:
        try:
            clean_choice = input("\nDo you want to delete any pre-existing monitoring alarms before deploying? [y/N]: ").strip().lower()
        except EOFError:
            clean_choice = 'n'
        if clean_choice == 'y':
            delete_old_alarms()

    # Phase 3: Security & Notifications
    logger.info("Starting Phase 3: Security & Notifications Setup")
    role_arn = setup_iam()
    
    # Auto configure SSM role for EC2 instances
    for inst in INVENTORY['ec2']:
        configure_ec2_ssm_permissions(inst['Id'])
        
    sns_arn = setup_sns()
    configure_ssm_webhooks()
    deploy_lambda_notifier(role_arn, sns_arn)
    
    # Phase 4: Compute & DB Monitoring Setup
    logger.info("Starting Phase 4: Compute & Database Monitoring Setup")
    deploy_cw_agent()
    time.sleep(2)
    configure_ec2_alarms(sns_arn)
    configure_rds_alarms(sns_arn)
    
    # Phase 5: Application & SSL Monitoring Setup
    logger.info("Starting Phase 5: Application & SSL Monitoring Setup")
    configure_ssl_monitor(role_arn, sns_arn)
    configure_web_monitoring()
    configure_database_monitoring()
    configure_application_monitoring(role_arn, sns_arn)
    
    # Phase 6: Account Auditing
    logger.info("Starting Phase 6: Account Auditing")
    configure_cloudtrail_auditing()
    
    # Phase 7: Dashboards
    logger.info("Starting Phase 7: Dashboard Generation")
    generate_dashboard()

    logger.info("Execution Completed Successfully.")
    print_summary()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nDeployment aborted by administrator.")
        logger.info("Execution aborted via KeyboardInterrupt.")
        print_summary()
        sys.exit(0)
    except Exception as e:
        logger.exception(f"Unhandled exception in setup execution: {e}")
        sys.exit(1)
