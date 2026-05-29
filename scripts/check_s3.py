"""Quick S3 connectivity check — verify real credentials work before the pipeline finishes."""
import boto3
from botocore.exceptions import ClientError, EndpointResolutionError

S3_ENDPOINT = "http://192.168.180.99:8000"
S3_BUCKET   = "cyberforce-ce"
ACCESS_KEY  = "PGQAWYOJBC2GAVNPIKI9"
SECRET_KEY  = "0F9homyBzSqDjBXkURjXB2uipnBmBhyxGGwdM6yH"

s3 = boto3.client(
    "s3",
    endpoint_url=S3_ENDPOINT,
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
    region_name="us-east-1",
)

# 1. List buckets
try:
    buckets = s3.list_buckets()
    print("✅ Auth OK — buckets:", [b["Name"] for b in buckets["Buckets"]])
except Exception as e:
    print(f"❌ Auth failed: {e}")

# 2. Check target bucket
try:
    s3.head_bucket(Bucket=S3_BUCKET)
    print(f"✅ Bucket '{S3_BUCKET}' exists and is accessible")
except ClientError as e:
    code = e.response["Error"]["Code"]
    print(f"❌ Bucket check failed ({code}): {e}")
except Exception as e:
    print(f"❌ Bucket check error: {e}")

# 3. Upload a test object
TEST_KEY = "auth-audit/screenshots/.connection-test"
try:
    s3.put_object(Bucket=S3_BUCKET, Key=TEST_KEY, Body=b"auth-audit connection test")
    url = f"{S3_ENDPOINT}/{S3_BUCKET}/{TEST_KEY}"
    print(f"✅ Upload OK: {url}")
    # Clean up
    s3.delete_object(Bucket=S3_BUCKET, Key=TEST_KEY)
    print("✅ Cleanup OK")
except Exception as e:
    print(f"❌ Upload failed: {e}")
