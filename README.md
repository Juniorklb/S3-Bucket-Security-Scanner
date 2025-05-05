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
## 🔧 Before Running:
- Make sure:

   - Your AWS credentials are configured with aws configure or via IAM role.

   - Boto3 is installed:
 
          pip install boto3
## Step 2: Public Access Check
Update your ``scanner.py`` to include this: 
def check_public_access(bucket_name):
    s3 = boto3.client('s3')
    public_access_blocked = True
    acl_public = False

    # Check Public Access Block configuration
    try:
        response = s3.get_bucket_policy_status(Bucket=bucket_name)
        is_public = response['PolicyStatus']['IsPublic']
        if is_public:
            public_access_blocked = False
    except ClientError as e:
        print(f"[{bucket_name}] No policy status or error: {e}")

    # Check ACL for public grants
    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        for grant in acl['Grants']:
            grantee = grant.get('Grantee', {})
            if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                acl_public = True
    except ClientError as e:
        print(f"[{bucket_name}] Error fetching ACL: {e}")

    return not public_access_blocked or acl_public
And modify the main block to include the check:

       if __name__ == "__main__":
       buckets = list_buckets()
       print("\n🛡️ Scanning Buckets for Public Access...")

    for bucket in buckets:
        is_public = check_public_access(bucket)
        status = "❌ Public!" if is_public else " Private"
        print(f" - {bucket}: {status}")
## Sample Output:
       🛡️ Scanning Buckets for Public Access...
       - my-private-bucket: ✅ Private
       - public-demo-bucket: ❌ Public!
## Step 3: Check Default Encryption Status
Add the following function to your ``scanner.py:``

    def check_encryption(bucket_name):
    s3 = boto3.client('s3')
    try:
        response = s3.get_bucket_encryption(Bucket=bucket_name)
        rules = response['ServerSideEncryptionConfiguration']['Rules']
        if rules:
            return True
    except ClientError as e:
        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
            return False
        else:
            print(f"[{bucket_name}] Error checking encryption: {e}")
    return False
    
## 🧩 Update main block to include encryption check:

    if __name__ == "__main__":
    buckets = list_buckets()
    print("\n🔐 Scanning Buckets for Public Access & Encryption...")

    for bucket in buckets:
        is_public = check_public_access(bucket)
        is_encrypted = check_encryption(bucket)

        public_status = "❌ Public!" if is_public else "✅ Private"
        encryption_status = "✅ Encrypted" if is_encrypted else "❌ Not Encrypted"

        print(f" - {bucket}: {public_status}, {encryption_status}")

 ### Sample Output:

- 🔐 Scanning Buckets for Public Access & Encryption...
 - my-secure-bucket: ✅ Private, ✅ Encrypted
 - dev-test-bucket: ❌ Public!, ❌ Not Encrypted

## Step 4: Check Versioning
Add the following function to your ``scanner.py``:

    def check_versioning(bucket_name):
    s3 = boto3.client('s3')
    try:
        response = s3.get_bucket_versioning(Bucket=bucket_name)
        status = response.get('Status', None)
        return status == 'Enabled'
    except ClientError as e:
        print(f"[{bucket_name}] Error checking versioning: {e}")
        return False
        
## Update the main block:

    if __name__ == "__main__":
    buckets = list_buckets()
    print("\n🔍 Scanning Buckets for Public Access, Encryption & Versioning...")

    for bucket in buckets:
        is_public = check_public_access(bucket)
        is_encrypted = check_encryption(bucket)
        versioning_enabled = check_versioning(bucket)

        public_status = "❌ Public!" if is_public else "✅ Private"
        encryption_status = "✅ Encrypted" if is_encrypted else "❌ Not Encrypted"
        versioning_status = "✅ Versioning ON" if versioning_enabled else "❌ Versioning OFF"

        print(f" - {bucket}: {public_status}, {encryption_status}, {versioning_status}")

## 🧪 Sample Output:
    🔍 Scanning Buckets for Public Access, Encryption & Versioning...
    - secure-bucket: ✅ Private, ✅ Encrypted, ✅ Versioning ON
    - demo-bucket: ❌ Public!, ❌ Not Encrypted, ❌ Versioning OFF
    
## Step 5: Check Logging Status
   Add this function to your ``scanner.py``:

     def check_logging(bucket_name):
      s3 = boto3.client('s3')
     try:
        response = s3.get_bucket_logging(Bucket=bucket_name)
        logging_config = response.get('LoggingEnabled')
        return logging_config is not None
    except ClientError as e:
        print(f"[{bucket_name}] Error checking logging: {e}")
        return False
### Update your main block again:

    if __name__ == "__main__":
    buckets = list_buckets()
    print("\n📋 Scanning Buckets for Security Best Practices...")

    for bucket in buckets:
        is_public = check_public_access(bucket)
        is_encrypted = check_encryption(bucket)
        versioning_enabled = check_versioning(bucket)
        logging_enabled = check_logging(bucket)

        public_status = "❌ Public!" if is_public else "✅ Private"
        encryption_status = "✅ Encrypted" if is_encrypted else "❌ Not Encrypted"
        versioning_status = "✅ Versioning ON" if versioning_enabled else "❌ Versioning OFF"
        logging_status = "✅ Logging ON" if logging_enabled else "❌ Logging OFF"

        print(f" - {bucket}: {public_status}, {encryption_status}, {versioning_status}, {logging_status}")
        
### Sample Output:

    📋 Scanning Buckets for Security Best Practices...
    - project-bucket: ✅ Private, ✅ Encrypted, ✅ Versioning ON, ✅ Logging ON
    - test-bucket: ❌ Public!, ❌ Not Encrypted, ❌ Versioning OFF, ❌ Logging OFF
    
## Step 6: Analyze Bucket Policy for Wildcard Access
Add this function to ``scanner.py``:

    import json

    def check_bucket_policy(bucket_name):
    s3 = boto3.client('s3')
    issues = []

    try:
        response = s3.get_bucket_policy(Bucket=bucket_name)
        policy = json.loads(response['Policy'])
        statements = policy.get('Statement', [])

        for stmt in statements:
            effect = stmt.get('Effect')
            principal = stmt.get('Principal')
            action = stmt.get('Action')
            resource = stmt.get('Resource')

            if effect == 'Allow' and principal == "*":
                issues.append(f"Wildcard Principal '*' allows {action} on {resource}")
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            pass  # No policy is okay
        else:
            print(f"[{bucket_name}] Error reading policy: {e}")
    return issues
## Final Update to the  ``main``  block:

    if __name__ == "__main__":
    buckets = list_buckets()
    print("\n🔎 Full S3 Bucket Security Scan\n")

    for bucket in buckets:
        is_public = check_public_access(bucket)
        is_encrypted = check_encryption(bucket)
        versioning_enabled = check_versioning(bucket)
        logging_enabled = check_logging(bucket)
        policy_issues = check_bucket_policy(bucket)

        public_status = "❌ Public!" if is_public else "✅ Private"
        encryption_status = "✅ Encrypted" if is_encrypted else "❌ Not Encrypted"
        versioning_status = "✅ Versioning ON" if versioning_enabled else "❌ Versioning OFF"
        logging_status = "✅ Logging ON" if logging_enabled else "❌ Logging OFF"

        print(f" - {bucket}: {public_status}, {encryption_status}, {versioning_status}, {logging_status}")
        if policy_issues:
            print("   ⚠️ Policy Issues:")
            for issue in policy_issues:
                print(f"     - {issue}")
### Sample Output:

    🔎 Full S3 Bucket Security Scan

    - secure-logs: ✅ Private, ✅ Encrypted, ✅ Versioning ON, ✅ Logging ON
    - demo-open: ❌ Public!, ❌ Not Encrypted, ❌ Versioning OFF, ❌ Logging OFF
     ⚠️ Policy Issues:
     - Wildcard Principal '*' allows s3:GetObject on arn:aws:s3:::demo-open/*
### Conclusion: S3 Bucket Security Scanner
- You've just built a fully functional S3 Bucket Security Scanner that performs key security audits for every S3 bucket in your AWS account. Here's a recap of what your scanner does:
