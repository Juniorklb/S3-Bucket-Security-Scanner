# 🛡️ S3 Bucket Security Scanner

The **S3 Bucket Security Scanner** is a Python-based tool that audits your AWS S3 buckets for common misconfigurations and security risks. It helps identify public access, missing encryption, unsafe permissions, and other potential vulnerabilities in your cloud storage.

---

## 🔧 Features

- 🔍 Detect publicly accessible buckets (read/write)
- 🔐 Check for server-side encryption (SSE)
- 📜 Analyze bucket policies and ACLs for overly permissive rules
- 🔁 Verify if versioning is enabled
- 📘 Check if access logging is activated
- 📊 Generate a summary report (CSV, JSON, or console)
- ⏱️ (Optional) Schedule periodic scans via AWS Lambda and CloudWatch

---

## 📦 Tech Stack

- **Python 3**
- **Boto3 (AWS SDK for Python)**
- **AWS IAM** (for authentication)
- Optional: **CloudWatch Logs**, **Lambda**, **DynamoDB**

---

## 🚀 Getting Started

### 1. Clone the Repository
bash

        git clone https://github.com/yourusername/s3-bucket-security-scanner.git
        cd s3-bucket-security-scanner
### Install Dependencies

      pip install -r requirements.txt
### Configure AWS Credentials
- Ensure you have an AWS CLI profile or environment variables set:

      aws configure
- Or use an IAM role if running in a cloud environment.

- Usage
- Run the scanner:
  
      python scanner.py
Optional arguments:

-``output json`` → export to JSON file

-``region us-east-1`` → scan specific region

### Sample Output

    {
    "BucketName": "example-bucket",
    "PublicAccess": true,
    "Encryption": false,
    "Versioning": true,
    "Logging": false,
    "PolicyIssues": ["Allow '*' on s3:GetObject"]
    }
## Step 1: Initialize and List S3 Buckets

    # scanner.py

     import boto3
     from botocore.exceptions import ClientError

    def list_buckets():
    s3 = boto3.client('s3')

    try:
        response = s3.list_buckets()
        buckets = [bucket['Name'] for bucket in response.get('Buckets', [])]
        return buckets
    except ClientError as e:
        print(f"Error listing buckets: {e}")
        return []

    if __name__ == "__main__":
    buckets = list_buckets()
    print("🪣 Found Buckets:")
    for bucket in buckets:
        print(f" - {bucket}")
