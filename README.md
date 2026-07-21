# AWS Infrastructure Monitoring Automation

This repository contains a robust, single-file Python automation script designed to automatically configure a complete, production-grade monitoring stack in AWS. It seamlessly integrates Amazon EC2, RDS, CloudWatch, Systems Manager (SSM), Lambda, and EventBridge to provide deep visibility into your infrastructure.

## Features

- **Automated CloudWatch Agent Deployment:** Automatically discovers all running EC2 instances, ensures they have the correct IAM roles for Systems Manager (SSM), and silently installs the CloudWatch Agent to monitor memory, disk, and processes.
- **Dynamic Alarms Generation:** Automatically generates CloudWatch Alarms for CPU, Memory, Disk Space, Free Inodes, Network Traffic, and Instance Status Checks.
- **Intelligent Process Detection:** Scans instances to detect running web servers (Nginx, Apache, IIS) and database engines (MySQL, PostgreSQL, MongoDB, Redis) and automatically configures process-level monitoring and alerting.
- **RDS Monitoring:** Automatically configures alarms for RDS CPU, Free Storage Space, Database Connections, and Replication Lag (for PostgreSQL).
- **SSL Certificate Monitoring:** Deploys a Lambda function to check external domain SSL certificates daily and alerts you via SNS before they expire.
- **Application Health Canaries:** Deploys AWS CloudWatch Synthetics (Node.js/Puppeteer) to monitor the uptime of your web applications.
- **Centralized Alerting Pipeline:** Routes all alerts to a central SNS topic. Includes a Lambda notification forwarder to push alerts to Slack, Microsoft Teams, or Telegram.
- **Interactive Approval Engine:** Operates safely by showing you exactly what AWS API calls are going to be made and prompting for your approval before modifying any infrastructure.

## Prerequisites

- AWS CloudShell (Recommended) or a local machine with AWS credentials configured.
- Python 3.7+
- `boto3` library (`pip install boto3`)

## Usage

For the safest and most reliable execution, we recommend running this script directly from **AWS CloudShell**, which comes pre-authenticated and pre-installed with Python and `boto3`.

1. Open AWS CloudShell from your AWS Management Console.
2. Upload the `aws_monitoring_setup.py` script.
3. Run the script:

```bash
# Run with interactive approvals (Recommended for first run)
python3 aws_monitoring_setup.py

# Run with auto-approval and clean up any old alarms created by the script
python3 aws_monitoring_setup.py --auto-approve --clean-alarms
```

## Security & Architecture

This script strictly adheres to the principle of least privilege.
- It dynamically creates IAM Roles and Instance Profiles specifically for monitoring.
- It uses Systems Manager (SSM) instead of SSH, meaning you do not need to open inbound ports or manage SSH keys to deploy the CloudWatch Agent.
- Webhook tokens and secrets are stored securely in AWS Systems Manager Parameter Store as `SecureString` types.
