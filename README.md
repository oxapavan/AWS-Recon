# Cloud Recon — Automated AWS Enumeration Tool  

## Introduction  

*Cloud Recon * is a Bash-based AWS enumeration tool designed to automate the discovery of IAM, S3, and EC2 resources within an AWS environment.  
This tool leverages AWS CLI and `jq` to collect detailed security-relevant information, generating a timestamped report for auditing and analysis.  


## Features  

### IAM Enumeration  
- Retrieves AWS account summary information.  
- Lists IAM users, groups, roles, and their respective permissions.  
- Enumerates attached and inline policies for users and groups.  
- Displays roles available for role assumption.  

### S3 Enumeration  
- Lists all S3 buckets in the target AWS environment.  
- Extracts S3 bucket policies for access control visibility.  
- Retrieves Access Control Lists (ACLs) for each bucket.  

### EC2 Enumeration  
- Discovers EC2 instances within the account.  
- Provides detailed attributes including:  
  - Instance ID  
  - Instance Name (from tags)  
  - Security Groups  
  - Availability Zone  
  - Instance State  

---

## Prerequisites  

Ensure the following tools are installed and configured:  

- [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)  
- [`jq`](https://stedolan.github.io/jq/download/) — Command-line JSON processor  

---

## AWS CLI Profile Setup  

Before running the script, configure your AWS CLI profile:  

```bash
aws configure --profile <your_profile_name>
