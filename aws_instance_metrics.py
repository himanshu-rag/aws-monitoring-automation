#!/usr/bin/env python3
"""
AWS EC2 Instance Metrics & Agent Installer Script
Queries CloudWatch for all available EC2 and CWAgent metrics for instances.
Also provides automated installation of the CloudWatch Agent via Systems Manager (SSM).
"""

import argparse
import datetime
import json
import sys
import time
import boto3
from botocore.exceptions import ClientError

# ANSI Color Formatting
GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
CYAN = "\033[0;36m"
BOLD = "\033[1m"
NC = "\033[0m" # No Color

def format_value(value, unit, metric_name):
    """
    Format metric value based on its unit or metric name for human-readable display.
    """
    if value is None:
        return "N/A"
        
    if not isinstance(value, (int, float)):
        return str(value)
    
    # Format bytes to human readable sizes
    is_bytes = (
        unit in ['Bytes', 'Bytes/Second'] or 
        any(x in metric_name.lower() for x in ['bytes', 'networkin', 'networkout', 'diskread', 'diskwrite'])
    )
    if is_bytes:
        for u in ['B', 'KB', 'MB', 'GB', 'TB']:
            if value < 1024.0:
                # If bytes/second, append /s
                suffix = "/s" if "second" in str(unit).lower() else ""
                return f"{value:.2f} {u}{suffix}"
            value /= 1024.0
            
    if unit == 'Percent' or 'percent' in metric_name.lower() or 'utilization' in metric_name.lower():
        return f"{value:.2f}%"
        
    if isinstance(value, int):
        return f"{value}"
        
    if isinstance(value, float):
        if value.is_integer():
            return f"{int(value)}"
        return f"{value:.2f}"
        
    return f"{value}"

def get_metric_statistic_type(metric_name):
    """
    Determine whether to use Average or Sum statistic based on metric characteristics.
    """
    sum_metrics = [
        'networkin', 'networkout', 'networkpacketsin', 'networkpacketsout',
        'diskreadops', 'diskwriteops', 'diskreadbytes', 'diskwritebytes',
        'ebsreadops', 'ebswriteops', 'ebsreadbytes', 'ebswritebytes'
    ]
    name_lower = metric_name.lower()
    if any(m in name_lower for m in sum_metrics):
        return 'Sum'
    return 'Average'

def ensure_instance_permissions(ec2_client, iam_client, instance_id):
    """
    Checks if an EC2 instance has the required IAM policies.
    If not, attempts to attach them to the existing role, or creates and attaches a new role.
    """
    print(f"[*] Checking IAM permissions for instance {instance_id}...")
    try:
        # 1. Get instance details to check for IAM Instance Profile
        inst_res = ec2_client.describe_instances(InstanceIds=[instance_id])
        reservations = inst_res.get('Reservations', [])
        if not reservations:
            return
        instance = reservations[0]['Instances'][0]
        
        iam_profile = instance.get('IamInstanceProfile')
        required_policies = [
            'arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy',
            'arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'
        ]
        
        role_name = None
        
        if iam_profile:
            # Instance has an IAM profile. We find the associated role and attach policies.
            profile_arn = iam_profile['Arn']
            profile_name = profile_arn.split('/')[-1]
            print(f"    [+] Instance already has profile: {profile_name}. Verifying policies...")
            try:
                prof_detail = iam_client.get_instance_profile(InstanceProfileName=profile_name)
                roles = prof_detail['InstanceProfile']['Roles']
                if roles:
                    role_name = roles[0]['RoleName']
                    print(f"    [+] Found associated role: {role_name}. Ensuring policies are attached...")
                    for policy_arn in required_policies:
                        try:
                            iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
                            print(f"      [✓] Attached policy: {policy_arn.split('/')[-1]}")
                        except ClientError as e:
                            print(f"      [!] Could not attach policy {policy_arn.split('/')[-1]}: {e.response['Error']['Message']}")
                else:
                    print(f"    [!] Instance profile {profile_name} has no roles associated.")
            except Exception as e:
                print(f"    [!] Error checking/modifying existing profile {profile_name}: {e}")
        else:
            # Instance has NO IAM profile. We must create and attach one.
            print("    [!] Instance has no IAM Instance Profile attached. Attempting to create and attach one...")
            role_name = "EC2-CloudWatchAgent-SSM-Role"
            profile_name = "EC2-CloudWatchAgent-SSM-Profile"
            
            # Trust relationship policy document for EC2
            trust_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "ec2.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            }
            
            # Create Role if not exists
            try:
                iam_client.create_role(
                    RoleName=role_name,
                    AssumeRolePolicyDocument=json.dumps(trust_policy),
                    Description="Role created by metrics script for CloudWatch Agent and SSM"
                )
                print(f"    [✓] Created IAM Role: {role_name}")
            except ClientError as e:
                if e.response['Error']['Code'] == 'EntityAlreadyExists':
                    print(f"    [+] IAM Role {role_name} already exists.")
                else:
                    print(f"    [!] Failed to create IAM Role {role_name}: {e}")
                    return
            except Exception as e:
                print(f"    [!] Failed to create IAM Role {role_name}: {e}")
                return
                
            # Attach policies to the role
            for policy_arn in required_policies:
                try:
                    iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
                    print(f"      [✓] Attached policy: {policy_arn.split('/')[-1]}")
                except Exception as e:
                    print(f"      [!] Failed to attach policy {policy_arn.split('/')[-1]}: {e}")
                    
            # Create Instance Profile if not exists
            profile_created = False
            try:
                iam_client.create_instance_profile(InstanceProfileName=profile_name)
                print(f"    [✓] Created Instance Profile: {profile_name}")
                profile_created = True
            except ClientError as e:
                if e.response['Error']['Code'] == 'EntityAlreadyExists':
                    print(f"    [+] Instance Profile {profile_name} already exists.")
                    profile_created = True
                else:
                    print(f"    [!] Failed to create Instance Profile {profile_name}: {e}")
            except Exception as e:
                print(f"    [!] Failed to create Instance Profile {profile_name}: {e}")
                
            if profile_created:
                # Add role to profile (ignore if already added)
                try:
                    iam_client.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
                    print(f"    [✓] Associated Role {role_name} with Profile {profile_name}")
                except Exception as e:
                    # Ignore if LimitExceeded/already associated
                    pass
                
                # Attach profile to instance
                print("    [*] Waiting 5 seconds for IAM Role propagation before attaching...")
                time.sleep(5)
                try:
                    ec2_client.associate_iam_instance_profile(
                        IamInstanceProfile={'Name': profile_name},
                        InstanceId=instance_id
                    )
                    print(f"    [✓] Successfully attached profile {profile_name} to instance {instance_id}")
                    # Give extra propagation time for EC2 to apply the profile
                    time.sleep(2)
                except Exception as e:
                    print(f"    [!] Failed to attach profile to instance {instance_id}: {e}")
                    
    except Exception as e:
        print(f"    [!] Permissions check failed: {e}")

def install_cloudwatch_agent(ssm_client, running_instance_ids, region):
    """
    Uses SSM Run Command to install and configure the CloudWatch Agent on running instances.
    """
    print(f"\n{YELLOW}=== Starting CloudWatch Agent Installation & Configuration ==={NC}")
    if not running_instance_ids:
        print(f"{RED}No running instances found to install the agent on.{NC}")
        return
        
    # Standard CloudWatch Agent Configuration JSON
    agent_config = {
        "agent": {
            "metrics_collection_interval": 60,
            "run_as_user": "cwagent"
        },
        "metrics": {
            "append_dimensions": {
                "InstanceId": "${aws:InstanceId}",
                "InstanceType": "${aws:InstanceType}"
            },
            "metrics_collected": {
                "mem": {
                    "measurement": [
                        "mem_used_percent"
                    ],
                    "metrics_collection_interval": 60
                },
                "disk": {
                    "measurement": [
                        "disk_used_percent"
                    ],
                    "metrics_collection_interval": 60,
                    "resources": [
                        "/"
                    ]
                }
            }
        }
    }
    
    parameter_name = "AmazonCloudWatch-AgentConfig-Default"
    
    # 1. Store/Update the configuration in SSM Parameter Store
    print(f"[*] Storing default config in SSM Parameter Store ({parameter_name})...")
    try:
        ssm_client.put_parameter(
            Name=parameter_name,
            Description="Default CloudWatch Agent config for memory and disk utilization",
            Value=json.dumps(agent_config, indent=2),
            Type="String",
            Overwrite=True
        )
        print(f"{GREEN}[+] Configuration stored successfully.{NC}")
    except ClientError as e:
        print(f"{RED}Failed to write configuration to Parameter Store: {e}{NC}")
        return
        
    # 2. Trigger installation of AmazonCloudWatchAgent package
    print(f"[*] Dispatching SSM Command to install Amazon CloudWatch Agent package on: {running_instance_ids}...")
    try:
        install_res = ssm_client.send_command(
            InstanceIds=running_instance_ids,
            DocumentName="AWS-ConfigureAWSPackage",
            Parameters={
                "action": ["Install"],
                "name": ["AmazonCloudWatchAgent"]
            }
        )
        install_cmd_id = install_res['Command']['CommandId']
        print(f"{GREEN}[+] Installation command dispatched (Command ID: {install_cmd_id}).{NC}")
    except ClientError as e:
        print(f"{RED}Failed to dispatch installation command: {e}{NC}")
        return

    # Wait briefly for installation to initiate
    print("[*] Waiting 10 seconds for installation to complete...")
    time.sleep(10)

    # 3. Configure and start the agent referencing the SSM parameter
    print(f"[*] Dispatching SSM Command to configure and start CloudWatch Agent...")
    try:
        config_res = ssm_client.send_command(
            InstanceIds=running_instance_ids,
            DocumentName="AmazonCloudWatch-ManageAgent",
            Parameters={
                "action": ["configure"],
                "mode": ["ec2"],
                "optionalConfigurationSource": ["ssm"],
                "optionalConfigurationLocation": [parameter_name],
                "optionalRestart": ["yes"]
            }
        )
        config_cmd_id = config_res['Command']['CommandId']
        print(f"{GREEN}[+] Configuration and Start command dispatched (Command ID: {config_cmd_id}).{NC}")
        print(f"\n{GREEN}[✓] CloudWatch Agent setup initiated. It may take 1-3 minutes for OS-level metrics to populate in CloudWatch.{NC}")
        print(f"{YELLOW}Note: Ensure target instances have an IAM Instance Profile attached with 'CloudWatchAgentServerPolicy' and 'AmazonSSMManagedInstanceCore' permissions.{NC}\n")
    except ClientError as e:
        print(f"{RED}Failed to dispatch configuration command: {e}{NC}")

def main():
    parser = argparse.ArgumentParser(description="AWS EC2 Dynamic CloudWatch Metric Fetcher & Installer")
    parser.add_argument("--region", default=None, help="Target AWS region (e.g. ap-south-1). Defaults to configured AWS CLI region.")
    parser.add_argument("--all-regions", action="store_true", help="Scan EC2 instances across all available AWS regions.")
    
    args = parser.parse_args()
    
    # Initialize boto3 session
    try:
        session = boto3.session.Session(region_name=args.region)
        region = session.region_name if args.region else boto3.client('ec2').meta.region_name
    except Exception as e:
        print(f"{RED}Error initializing AWS Session: {e}. Check your credentials/configuration.{NC}")
        sys.exit(1)
        
    if not region:
        print(f"{RED}No AWS region specified or found. Please use --region or configure default region.{NC}")
        sys.exit(1)
        
    print(f"{BLUE}============================================================={NC}")
    print(f"{BLUE}   AWS EC2 DYNAMIC METRICS REPORTER (Target Region: {region}) {NC}")
    print(f"{BLUE}============================================================={NC}")
    
    ec2_client = boto3.client('ec2', region_name=region)
    cw_client = boto3.client('cloudwatch', region_name=region)
    ssm_client = boto3.client('ssm', region_name=region)
    iam_client = boto3.client('iam')
    
    # 1. Discover EC2 Instances
    print("[*] Discovering EC2 instances...")
    try:
        instances_res = ec2_client.describe_instances()
    except ClientError as e:
        print(f"{RED}Failed to query EC2 instances: {e}{NC}")
        sys.exit(1)
        
    instances = []
    running_ids = []
    
    for reservation in instances_res.get('Reservations', []):
        for inst in reservation.get('Instances', []):
            inst_id = inst['InstanceId']
            state = inst['State']['Name']
            inst_type = inst['InstanceType']
            
            # Extract Name Tag
            name = "Unknown"
            for tag in inst.get('Tags', []):
                if tag['Key'] == 'Name':
                    name = tag['Value']
                    break
                    
            instances.append({
                'id': inst_id,
                'name': name,
                'state': state,
                'type': inst_type,
                'private_ip': inst.get('PrivateIpAddress', 'N/A'),
                'public_ip': inst.get('PublicIpAddress', 'N/A')
            })
            
            if state == 'running':
                running_ids.append(inst_id)
                
    if not instances:
        print(f"{YELLOW}No EC2 instances found in region {region}.{NC}")
        return
        
    print(f"{GREEN}[+] Found {len(instances)} instances ({len(running_ids)} running).{NC}")
    
    # Automatically install/configure the CloudWatch Agent via SSM on all running instances
    if running_ids:
        # First, ensure the instances have the necessary IAM permissions
        print(f"\n{YELLOW}=== Verifying and Setting Up Required IAM Permissions ==={NC}")
        for inst_id in running_ids:
            ensure_instance_permissions(ec2_client, iam_client, inst_id)
            
        # Now install/configure the agent
        install_cloudwatch_agent(ssm_client, running_ids, region)
        
    # 2. Gather metrics for each running instance
    now = datetime.datetime.now(datetime.timezone.utc)
    start_time = now - datetime.timedelta(hours=1)
    
    for inst in instances:
        inst_id = inst['id']
        name = inst['name']
        state = inst['state']
        
        state_color = GREEN if state == "running" else (RED if state == "stopped" else YELLOW)
        print(f"\n{BOLD}Instance:{NC} {CYAN}{name}{NC} ({inst_id})")
        print(f"  State: {state_color}{state}{NC} | Type: {inst['type']} | Private IP: {inst['private_ip']} | Public IP: {inst['public_ip']}")
        
        if state != 'running':
            print(f"  {YELLOW}Instance is not running. CloudWatch does not report active metrics for stopped instances.{NC}")
            continue
            
        print("  [*] Querying available metric definitions from CloudWatch...")
        
        # Discover all available metrics for this instance (from AWS/EC2 and CWAgent namespaces)
        discovered_metrics = []
        for namespace in ['AWS/EC2', 'CWAgent']:
            try:
                paginator = cw_client.get_paginator('list_metrics')
                metric_iterator = paginator.paginate(
                    Namespace=namespace,
                    Dimensions=[{'Name': 'InstanceId', 'Value': inst_id}]
                )
                for page in metric_iterator:
                    for m in page.get('Metrics', []):
                        discovered_metrics.append({
                            'Namespace': namespace,
                            'MetricName': m['MetricName'],
                            'Dimensions': m['Dimensions']
                        })
            except Exception as e:
                print(f"    {RED}Failed to list metrics for namespace {namespace}: {e}{NC}")
                
        if not discovered_metrics:
            print(f"  {YELLOW}No metric records found in CloudWatch for this instance yet.{NC}")
            continue
            
        print(f"  {GREEN}[+] Found {len(discovered_metrics)} active metrics. Querying values...{NC}")
        
        # Query metrics in batches (get_metric_data limit is 500 per call, we do all at once if <= 500)
        metric_queries = []
        query_map = {}
        
        for idx, m in enumerate(discovered_metrics):
            query_id = f"m_{idx}"
            stat = get_metric_statistic_type(m['MetricName'])
            metric_queries.append({
                'Id': query_id,
                'MetricStat': {
                    'Metric': {
                        'Namespace': m['Namespace'],
                        'MetricName': m['MetricName'],
                        'Dimensions': m['Dimensions']
                    },
                    'Period': 300, # 5 min resolution
                    'Stat': stat
                },
                'ReturnData': True
            })
            query_map[query_id] = {
                'Namespace': m['Namespace'],
                'MetricName': m['MetricName'],
                'Stat': stat
            }
            
        # Call get_metric_data (handling max 500 metrics per request)
        results = {}
        batch_size = 400
        for i in range(0, len(metric_queries), batch_size):
            batch = metric_queries[i:i+batch_size]
            try:
                data_response = cw_client.get_metric_data(
                    MetricDataQueries=batch,
                    StartTime=start_time,
                    EndTime=now
                )
                for r in data_response.get('MetricDataResults', []):
                    r_id = r['Id']
                    vals = r.get('Values', [])
                    unit = r.get('Unit', 'None')
                    # Get latest datapoint
                    val = vals[0] if vals else None
                    results[r_id] = {'value': val, 'unit': unit}
            except ClientError as e:
                print(f"    {RED}Error fetching metric batch: {e}{NC}")
                
        # Print table of metrics
        print(f"\n  {'Metric Name':<35} | {'Source':<10} | {'Latest Value':<15} | {'Stat':<8} | {'Unit':<12}")
        print("  " + "-" * 88)
        
        # Sort by namespace and metric name
        sorted_queries = sorted(query_map.keys(), key=lambda k: (query_map[k]['Namespace'], query_map[k]['MetricName']))
        
        for q_id in sorted_queries:
            q_info = query_map[q_id]
            res = results.get(q_id, {'value': None, 'unit': 'None'})
            
            metric_name = q_info['MetricName']
            namespace_short = "EC2" if q_info['Namespace'] == "AWS/EC2" else "CWAgent"
            val_formatted = format_value(res['value'], res['unit'], metric_name)
            stat = q_info['Stat']
            unit_str = res['unit'] if res['unit'] != 'None' else '-'
            
            # Highlights metrics with special colors for better readability
            color_prefix = ""
            if "cpu" in metric_name.lower():
                color_prefix = GREEN
            elif "mem" in metric_name.lower():
                color_prefix = CYAN
            elif "disk" in metric_name.lower():
                color_prefix = YELLOW
                
            # Calculate spacing based on visible characters, ignoring ANSI escape color codes
            padding = 35 - len(metric_name)
            if color_prefix:
                metric_name_colored = f"{color_prefix}{metric_name}{NC}" + " " * padding
            else:
                metric_name_colored = metric_name + " " * padding
            
            print(f"  {metric_name_colored} | {namespace_short:<10} | {val_formatted:<15} | {stat:<8} | {unit_str:<12}")
            
        print("  " + "-" * 88)
        
    print(f"\n{BLUE}============================================================={NC}")
    print(f"{YELLOW}Metrics check complete.{NC}")
    print(f"Note: CloudWatch Agent installation was automatically initiated via SSM. If this was the first run, OS-level metrics (CWAgent source) will take 1-3 minutes to begin appearing.")
    print(f"{BLUE}============================================================={NC}")

if __name__ == "__main__":
    main()
