import boto3

ec2 = boto3.client('ec2', region_name='ap-south-1')
inst_id = 'i-0525d78eada819d8f'

try:
    res = ec2.describe_instances(InstanceIds=[inst_id])
    if res['Reservations']:
        inst = res['Reservations'][0]['Instances'][0]
        print(f"Instance {inst_id} State: {inst['State']['Name']}")
    else:
        print(f"Instance {inst_id} not found.")
except Exception as e:
    print(f"Error: {e}")
