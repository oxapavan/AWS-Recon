import argparse
import json
import sys
from datetime import datetime
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, NoRegionError

class AWSScanner:
    def __init__(self, profile_name):
        self.profile_name = profile_name
        self.output_file = f"{profile_name}_enum_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
        self.colors = {
            'GREEN': '\033[0;32m',
            'YELLOW': '\033[0;33m',
            'RED': '\033[0;31m',
            'NC': '\033[0m'  # No Color
        }
        
        try:
            self.session = boto3.Session(profile_name=self.profile_name)
            self.sts_client = self.session.client('sts')
            self.iam_client = self.session.client('iam')
            self.s3_client = self.session.client('s3')
            self.ec2_client = self.session.client('ec2')
        except (NoCredentialsError, NoRegionError) as e:
            self.print_error(f"Configuration error: {str(e)}")
            sys.exit(1)

    def print_color(self, message, color):
        """Print colored message to console and write raw text to file"""
        if color not in self.colors:
            color = 'NC'
        colored_message = f"{self.colors[color]}{message}{self.colors['NC']}"
        print(colored_message)
        
        # Write to file without color codes
        with open(self.output_file, 'a') as f:
            f.write(f"{message}\n")

    def print_error(self, message):
        self.print_color(message, 'RED')

    def print_warning(self, message):
        self.print_color(message, 'YELLOW')

    def print_success(self, message):
        self.print_color(message, 'GREEN')

    def get_caller_identity(self):
        try:
            response = self.sts_client.get_caller_identity()
            return response['Arn'].split('/')[1]
        except ClientError as e:
            self.print_error(f"Error getting caller identity: {str(e)}")
            return None

    def iam_enumeration(self, username):
        self.print_warning("\nIAM Enumeration:")

        # Account Summary
        try:
            summary = self.iam_client.get_account_summary()
            self.print_success("[+] Account Summary:")
            summary_data = summary['SummaryMap']
            formatted_summary = (
                f"Policies: {summary_data.get('Policies', 'N/A')}\n"
                f"InstanceProfiles: {summary_data.get('InstanceProfiles', 'N/A')}\n"
                f"Users: {summary_data.get('Users', 'N/A')}\n"
                f"AccountMFAEnabled: {summary_data.get('AccountMFAEnabled', 'N/A')}\n"
                f"AccessKeysPerUserQuota: {summary_data.get('AccessKeysPerUserQuota', 'N/A')}\n"
                f"Groups: {summary_data.get('Groups', 'N/A')}\n"
                f"MFADevices: {summary_data.get('MFADevices', 'N/A')}\n"
                f"Roles: {summary_data.get('Roles', 'N/A')}\n"
            )
            self.print_color(formatted_summary, 'GREEN')
        except ClientError as e:
            self.print_error(f"[-] Access Denied: {str(e)}")

        # User Groups and Policies
        try:
            groups = self.iam_client.list_groups_for_user(UserName=username)
            if not groups['Groups']:
                self.print_error("[-] No groups found")
                return

            self.print_success("[+] Groups found:")
            for group in groups['Groups']:
                group_name = group['GroupName']
                self.print_color(f"  {group_name}", 'GREEN')

                # Attached group policies
                attached_policies = self.iam_client.list_attached_group_policies(
                    GroupName=group_name
                )
                self.process_policies(attached_policies, group_name, 'group')

                # Inline group policies
                inline_policies = self.iam_client.list_group_policies(GroupName=group_name)
                self.process_inline_policies(inline_policies, group_name, 'group')

        except ClientError as e:
            self.print_error(f"[-] Error listing groups: {str(e)}")

    def process_policies(self, policies, entity_name, entity_type):
        if not policies.get('AttachedPolicies'):
            self.print_error(f"  [-] No attached policies found for {entity_type} {entity_name}")
            return

        self.print_success(f"  [+] Attached Policies for {entity_type} {entity_name}:")
        for policy in policies['AttachedPolicies']:
            policy_arn = policy['PolicyArn']
            self.print_color(f"    {policy_arn}", 'GREEN')
            
            try:
                policy_ver = self.iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
                policy_doc = self.iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy_ver
                )['PolicyVersion']['Document']
                
                self.print_policy_statements(policy_doc)
                
            except ClientError as e:
                self.print_error(f"    [-] Error getting policy: {str(e)}")

    def process_inline_policies(self, policies, entity_name, entity_type):
        if not policies.get('PolicyNames'):
            self.print_error(f"  [-] No inline policies found for {entity_type} {entity_name}")
            return

        self.print_success(f"  [+] Inline Policies for {entity_type} {entity_name}:")
        for policy_name in policies['PolicyNames']:
            try:
                if entity_type == 'group':
                    policy_doc = self.iam_client.get_group_policy(
                        GroupName=entity_name,
                        PolicyName=policy_name
                    )['PolicyDocument']
                else:
                    policy_doc = self.iam_client.get_user_policy(
                        UserName=entity_name,
                        PolicyName=policy_name
                    )['PolicyDocument']
                
                self.print_color(f"    {policy_name}", 'GREEN')
                self.print_policy_statements(policy_doc)
                
            except ClientError as e:
                self.print_error(f"    [-] Error getting inline policy: {str(e)}")

    def print_policy_statements(self, policy_doc):
        for statement in policy_doc.get('Statement', []):
            effect = statement.get('Effect', 'N/A')
            actions = ', '.join(statement['Action']) if isinstance(statement['Action'], list) else statement.get('Action', 'N/A')
            resources = ', '.join(statement['Resource']) if isinstance(statement['Resource'], list) else statement.get('Resource', 'N/A')
            
            output = (
                f"        Effect: {effect}\n"
                f"        Action: {actions}\n"
                f"        Resource: {resources}\n"
            )
            self.print_color(output, 'GREEN')

    def s3_enumeration(self):
        self.print_warning("\nS3 Enumeration:")
        
        try:
            buckets = self.s3_client.list_buckets()['Buckets']
            if not buckets:
                self.print_error("[-] No buckets found")
                return

            self.print_success("[+] Buckets found:")
            for bucket in buckets:
                bucket_name = bucket['Name']
                self.print_color(f"  {bucket_name}", 'GREEN')
                
                # Bucket Policy
                try:
                    policy = self.s3_client.get_bucket_policy(Bucket=bucket_name)
                    self.print_policy(policy.get('Policy'))
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                        self.print_error("  [-] No bucket policy")
                    else:
                        self.print_error(f"  [-] Error getting policy: {str(e)}")
                
                # Bucket ACL
                try:
                    acl = self.s3_client.get_bucket_acl(Bucket=bucket_name)
                    self.process_acl(acl)
                except ClientError as e:
                    self.print_error(f"  [-] Error getting ACL: {str(e)}")

        except ClientError as e:
            self.print_error(f"[-] S3 Access Denied: {str(e)}")

    def process_acl(self, acl):
        for grant in acl.get('Grants', []):
            grantee = grant.get('Grantee', {})
            permission = grant.get('Permission', 'N/A')
            grantee_id = grantee.get('ID', 'N/A')
            self.print_color(f"    ID: {grantee_id}, Permission: {permission}", 'GREEN')

    def ec2_enumeration(self):
        self.print_warning("\nEC2 Enumeration:")
        
        try:
            instances = self.ec2_client.describe_instances()['Reservations']
            if not instances:
                self.print_error("[-] No EC2 instances found")
                return

            self.print_success("[+] EC2 Instances found:")
            for idx, reservation in enumerate(instances, 1):
                for instance in reservation['Instances']:
                    self.print_instance_details(instance, idx)
        except ClientError as e:
            self.print_error(f"[-] EC2 Access Denied: {str(e)}")

    def print_instance_details(self, instance, idx):
        name = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), 'N/A')
        output = (
            f"{idx}. Instance Name: {name}\n"
            f"   Instance ID: {instance['InstanceId']}\n"
            f"   State: {instance['State']['Name']}\n"
            f"   Private IP: {instance.get('PrivateIpAddress', 'N/A')}\n"
        )
        self.print_color(output, 'GREEN')

    def run(self):
        username = self.get_caller_identity()
        if not username:
            self.print_error("[-] Couldn't determine username")
            return

        self.print_success(f"\n[+] Username: {username}")
        self.iam_enumeration(username)
        self.s3_enumeration()
        self.ec2_enumeration()
        self.print_color("\nScan completed. Results saved to: " + self.output_file, 'GREEN')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='AWS Environment Scanner')
    parser.add_argument('profile_name', help='AWS profile name')
    args = parser.parse_args()

    scanner = AWSScanner(args.profile_name)
    scanner.run()