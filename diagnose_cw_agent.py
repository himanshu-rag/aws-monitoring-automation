"""
CloudWatch Agent Diagnostic Script
Run this in AWS CloudShell to see exactly why Memory/Disk metrics are missing.
Usage: python3 diagnose_cw_agent.py
"""

import boto3
import json
import time

ssm = boto3.client('ssm')
cw  = boto3.client('cloudwatch')

# ── 1. Find all SSM-managed instances ──────────────────────────────────────
print("\n" + "="*70)
print("STEP 1: Discovering SSM-managed instances...")
print("="*70)

instances = []
try:
    paginator = ssm.get_paginator('describe_instance_information')
    for page in paginator.paginate():
        for inst in page.get('InstanceInformationList', []):
            instances.append(inst['InstanceId'])
            print(f"  ✅ Found SSM instance: {inst['InstanceId']}  (Platform: {inst.get('PlatformName','?')}  Agent: {inst.get('AgentVersion','?')})")
except Exception as e:
    print(f"  ❌ Error: {e}")

if not instances:
    print("\n⛔ NO SSM INSTANCES FOUND!")
    print("   This means your EC2 instances do NOT have the SSM/CloudWatch IAM role attached.")
    print("   Re-run aws_monitoring_setup.py to attach roles, then wait 5 minutes.")
    exit(1)

print(f"\n  Total: {len(instances)} SSM instance(s) found.\n")

# ── 2. Check CloudWatch Agent status on every instance ─────────────────────
print("="*70)
print("STEP 2: Checking CloudWatch Agent status on each instance...")
print("="*70)

def run_and_wait(instance_id, command):
    try:
        resp = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [command]},
            TimeoutSeconds=30,
        )
        cmd_id = resp['Command']['CommandId']
        time.sleep(4)
        for _ in range(12):
            try:
                inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
                if inv['Status'] in ['Success', 'Failed', 'TimedOut', 'Cancelled']:
                    return inv.get('StandardOutputContent', '').strip(), inv.get('StandardErrorContent', '').strip(), inv['Status']
            except ssm.exceptions.InvocationDoesNotExist:
                pass
            time.sleep(3)
        return '', '', 'Timeout'
    except Exception as e:
        return '', str(e), 'Error'

for inst_id in instances:
    print(f"\n{'─'*60}")
    print(f"Instance: {inst_id}")
    print(f"{'─'*60}")

    # Check if agent binary exists
    stdout, stderr, status = run_and_wait(
        inst_id,
        "ls /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl 2>/dev/null && echo 'BINARY_EXISTS' || echo 'NOT_INSTALLED'"
    )
    if 'BINARY_EXISTS' in stdout:
        print(f"  ✅ CloudWatch Agent binary: INSTALLED")
    else:
        print(f"  ❌ CloudWatch Agent binary: NOT INSTALLED")
        print(f"     Fix: The installation SSM command failed or is still running.")
        continue

    # Check agent running status
    stdout, stderr, status = run_and_wait(
        inst_id,
        "/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -m ec2 -a status 2>&1"
    )
    print(f"  📊 Agent Status:")
    for line in stdout.splitlines():
        print(f"     {line}")

    # Check config file
    stdout2, _, _ = run_and_wait(
        inst_id,
        "cat /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json 2>/dev/null || echo 'NO_CONFIG_FILE'"
    )
    if 'NO_CONFIG_FILE' in stdout2 or not stdout2:
        print(f"  ❌ CloudWatch Agent config: MISSING (agent was never configured)")
    else:
        print(f"  ✅ CloudWatch Agent config: EXISTS")
        try:
            cfg = json.loads(stdout2)
            collected = cfg.get('metrics', {}).get('metrics_collected', {})
            print(f"     Metrics collected: {list(collected.keys())}")
        except Exception:
            print(f"     (Could not parse config)")

    # Check agent log for errors
    stdout3, _, _ = run_and_wait(
        inst_id,
        "tail -20 /opt/aws/amazon-cloudwatch-agent/logs/amazon-cloudwatch-agent.log 2>/dev/null || echo 'NO_LOG_FILE'"
    )
    if 'NO_LOG_FILE' in stdout3 or not stdout3:
        print(f"  ⚠️  Agent log: NOT FOUND (agent may never have started)")
    else:
        print(f"  📋 Last 20 lines of agent log:")
        for line in stdout3.splitlines():
            print(f"     {line}")

# ── 3. Check CWAgent metrics in CloudWatch ─────────────────────────────────
print("\n" + "="*70)
print("STEP 3: Checking if CWAgent metrics exist in CloudWatch...")
print("="*70)

try:
    metrics = cw.list_metrics(Namespace="CWAgent")
    found = metrics.get('Metrics', [])
    if found:
        print(f"  ✅ {len(found)} CWAgent metric(s) found in CloudWatch!")
        for m in found[:10]:
            dims = {d['Name']: d['Value'] for d in m.get('Dimensions', [])}
            print(f"     - {m['MetricName']}  {dims}")
    else:
        print("  ❌ ZERO CWAgent metrics found in CloudWatch!")
        print("     This confirms the agent is NOT sending any data.")
except Exception as e:
    print(f"  ❌ Error: {e}")

# ── 4. Check SSM Parameter Store for config ────────────────────────────────
print("\n" + "="*70)
print("STEP 4: Checking SSM Parameter Store for CloudWatch Agent config...")
print("="*70)
try:
    param = ssm.get_parameter(Name="AmazonCloudWatch-StandardConfig")
    value = param['Parameter']['Value']
    cfg = json.loads(value)
    collected = cfg.get('metrics', {}).get('metrics_collected', {})
    print(f"  ✅ Parameter exists! Metrics configured: {list(collected.keys())}")
except ssm.exceptions.ParameterNotFound:
    print("  ❌ Parameter 'AmazonCloudWatch-StandardConfig' NOT FOUND!")
    print("     This means store_agent_config() failed. Re-run the main script.")
except Exception as e:
    print(f"  ❌ Error: {e}")

print("\n" + "="*70)
print("DIAGNOSIS COMPLETE")
print("="*70)
