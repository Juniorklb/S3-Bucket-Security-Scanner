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
```bash
git clone https://github.com/yourusername/s3-bucket-security-scanner.git
cd s3-bucket-security-scanner
