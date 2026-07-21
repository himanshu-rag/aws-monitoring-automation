"""
Emergency Fix Script - Fixes CW Agent metric names and alarm dimensions.
Run in AWS CloudShell: python3 fix_cw_agent.py
"""
import boto3
import json
import time

ssm = boto3.client('ssm')
cw  = boto3.client('cloudwatch')

# ── Discovered from diagnostic output ─────────────────────────────────────
INSTANCES = {
    "i-005ed86f33239ddd4": {"type": "t3a.medium", "device": "nvme0n1p1", "fstype": "ext4", "path": "/"},
    "i-0eeedcbc260e559e5": {"type": "t3a.medium", "device": "nvme0n1p1", "fstype": "ext4", "path": "/"},
    "i-05733d451372b6b64": {"type": "t3a.large",  "device": "nvme0n1p1", "fstype": "ext4", "path": "/"},
}

SNS_TOPIC = None
try:
    sns_client = boto3.client('sns')
    topics = sns_client.list_topics().get('Topics', [])
    for t in topics:
        if 'InfrastructureAlerts' in t['TopicArn']:
            SNS_TOPIC = t['TopicArn']
            break
    print(f"✅ Found SNS Topic: {SNS_TOPIC}")
except Exception as e:
    print(f"⚠️  Could not find SNS topic: {e}")

if not SNS_TOPIC:
    print("❌ No SNS topic found. Alarms will be created without actions.")

print("\n" + "="*70)
print("STEP 1: Reconfiguring CloudWatch Agent on all instances...")
print("="*70)

# The correct config JSON with proper metric names
CW_CONFIG = {
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
            "mem": {
                "measurement": ["mem_used_percent"],
                "metrics_collection_interval": 60
            },
            "disk": {
                "measurement": ["used_percent", "inodes_free"],
                "metrics_collection_interval": 60,
                "resources": ["/"]
            },
            "swap": {
                "measurement": ["swap_used_percent"],
                "metrics_collection_interval": 60
            },
            "net": {
                "measurement": ["bytes_sent", "bytes_recv"],
                "metrics_collection_interval": 60
            }
        }
    }
}

config_json = json.dumps(CW_CONFIG)

def run_shell(instance_id, command, wait=True):
    try:
        resp = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [command]},
            TimeoutSeconds=60,
        )
        cmd_id = resp['Command']['CommandId']
        if not wait:
            return True, ""
        time.sleep(5)
        for _ in range(15):
            try:
                inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
                if inv['Status'] in ['Success', 'Failed', 'TimedOut']:
                    return inv['Status'] == 'Success', inv.get('StandardOutputContent','') + inv.get('StandardErrorContent','')
            except ssm.exceptions.InvocationDoesNotExist:
                pass
            time.sleep(3)
        return False, "Timeout"
    except Exception as e:
        return False, str(e)

for inst_id, meta in INSTANCES.items():
    print(f"\n{'─'*60}")
    print(f"Configuring: {inst_id}")
    print(f"{'─'*60}")

    # Write config file directly to the server
    write_cmd = f"echo '{config_json}' > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json"
    ok, out = run_shell(inst_id, write_cmd)
    print(f"  {'✅' if ok else '❌'} Wrote config file: {'OK' if ok else out[:100]}")

    # Restart agent with the new config
    restart_cmd = "/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -m ec2 -a fetch-config -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s"
    ok, out = run_shell(inst_id, restart_cmd)
    print(f"  {'✅' if ok else '❌'} Restarted agent: {'OK' if ok else out[:200]}")

    # Verify it's running
    status_cmd = "/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -m ec2 -a status"
    ok, out = run_shell(inst_id, status_cmd)
    try:
        status = json.loads(out)
        print(f"  📊 Status: {status.get('status')} | Config: {status.get('configstatus')}")
    except:
        print(f"  📊 Status output: {out[:100]}")

print("\n" + "="*70)
print("STEP 2: Waiting 90 seconds for agents to start sending metrics...")
print("="*70)
for i in range(9):
    time.sleep(10)
    print(f"  Waited {(i+1)*10}s...")

print("\n" + "="*70)
print("STEP 3: Deleting old broken alarms and creating correct ones...")
print("="*70)

OLD_ALARM_PREFIXES = ["EC2-Memory-", "EC2-Swap-", "EC2-DiskUsed-", "EC2-DiskInodes-"]
old_alarms = []
try:
    paginator = cw.get_paginator('describe_alarms')
    for page in paginator.paginate():
        for alarm in page.get('MetricAlarms', []):
            if any(alarm['AlarmName'].startswith(p) for p in OLD_ALARM_PREFIXES):
                old_alarms.append(alarm['AlarmName'])
    if old_alarms:
        cw.delete_alarms(AlarmNames=old_alarms)
        print(f"  ✅ Deleted {len(old_alarms)} old broken alarms: {old_alarms}")
    else:
        print("  ℹ️  No old alarms found to delete.")
except Exception as e:
    print(f"  ⚠️  Could not delete old alarms: {e}")

# Create correct alarms with correct metric names and dimensions
alarm_actions = [SNS_TOPIC] if SNS_TOPIC else []

for inst_id, meta in INSTANCES.items():
    inst_type = meta['type']
    device    = meta['device']
    fstype    = meta['fstype']
    path      = meta['path']

    print(f"\n  Creating alarms for {inst_id}...")

    # Memory alarm — correct dimensions include InstanceType
    try:
        cw.put_metric_alarm(
            AlarmName=f"EC2-Memory-{inst_id}",
            AlarmDescription=f"Memory > 85% on {inst_id}",
            ActionsEnabled=True,
            AlarmActions=alarm_actions,
            MetricName="mem_used_percent",
            Namespace="CWAgent",
            Statistic="Average",
            Dimensions=[
                {"Name": "InstanceId",   "Value": inst_id},
                {"Name": "InstanceType", "Value": inst_type}
            ],
            Period=60,
            EvaluationPeriods=2,
            Threshold=85.0,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="missing"
        )
        print(f"    ✅ EC2-Memory-{inst_id}")
    except Exception as e:
        print(f"    ❌ Memory alarm failed: {e}")

    # Swap alarm
    try:
        cw.put_metric_alarm(
            AlarmName=f"EC2-Swap-{inst_id}",
            AlarmDescription=f"Swap > 50% on {inst_id}",
            ActionsEnabled=True,
            AlarmActions=alarm_actions,
            MetricName="swap_used_percent",
            Namespace="CWAgent",
            Statistic="Average",
            Dimensions=[
                {"Name": "InstanceId",   "Value": inst_id},
                {"Name": "InstanceType", "Value": inst_type}
            ],
            Period=60,
            EvaluationPeriods=2,
            Threshold=50.0,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="missing"
        )
        print(f"    ✅ EC2-Swap-{inst_id}")
    except Exception as e:
        print(f"    ❌ Swap alarm failed: {e}")

    # Disk alarm — correct metric name is disk_used_percent
    try:
        cw.put_metric_alarm(
            AlarmName=f"EC2-DiskUsed-{inst_id}",
            AlarmDescription=f"Disk > 60% on {inst_id}",
            ActionsEnabled=True,
            AlarmActions=alarm_actions,
            MetricName="disk_used_percent",
            Namespace="CWAgent",
            Statistic="Average",
            Dimensions=[
                {"Name": "InstanceId",   "Value": inst_id},
                {"Name": "InstanceType", "Value": inst_type},
                {"Name": "path",         "Value": path},
                {"Name": "device",       "Value": device},
                {"Name": "fstype",       "Value": fstype}
            ],
            Period=60,
            EvaluationPeriods=2,
            Threshold=60.0,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="missing"
        )
        print(f"    ✅ EC2-DiskUsed-{inst_id}")
    except Exception as e:
        print(f"    ❌ Disk alarm failed: {e}")

print("\n" + "="*70)
print("STEP 4: Updating CloudWatch Dashboard with correct metric names...")
print("="*70)

ec2_mem_metrics = []
ec2_disk_metrics = []

for inst_id, meta in INSTANCES.items():
    inst_type = meta['type']
    device    = meta['device']
    fstype    = meta['fstype']
    path      = meta['path']
    ec2_mem_metrics.append([
        "CWAgent", "mem_used_percent",
        "InstanceId", inst_id,
        "InstanceType", inst_type,
        {"label": inst_id}
    ])
    ec2_disk_metrics.append([
        "CWAgent", "disk_used_percent",
        "InstanceId", inst_id,
        "InstanceType", inst_type,
        "path", path,
        "device", device,
        "fstype", fstype,
        {"label": f"{inst_id} Disk"}
    ])

# Fetch existing dashboard and patch the memory and disk widgets
try:
    dash = cw.get_dashboard(DashboardName="Infrastructure-Overview")
    body = json.loads(dash['DashboardBody'])
    for widget in body.get('widgets', []):
        props = widget.get('properties', {})
        title = props.get('title', '')
        if title == "EC2 Memory Utilization (%)":
            props['metrics'] = ec2_mem_metrics
            print("  ✅ Patched EC2 Memory widget")
        elif title == "EC2 Disk Utilization (%)":
            props['metrics'] = ec2_disk_metrics
            print("  ✅ Patched EC2 Disk widget")

    cw.put_dashboard(
        DashboardName="Infrastructure-Overview",
        DashboardBody=json.dumps(body)
    )
    print("  ✅ Dashboard updated successfully!")
except Exception as e:
    print(f"  ❌ Dashboard update failed: {e}")

print("\n" + "="*70)
print("ALL DONE!")
print("="*70)
print("\nWait 2-3 minutes then refresh your CloudWatch Dashboard.")
print("Memory and Disk graphs should now show live data!")
