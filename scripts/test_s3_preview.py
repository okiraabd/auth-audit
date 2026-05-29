"""Upload a test image with ContentType to verify preview works."""
import boto3

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

TEST_KEY = "auth-audit/test-image-preview.png"
# 1x1 transparent PNG
DUMMY_PNG = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x0bIDAT\x08\xd7c\x60\x00\x02\x00\x00\x05\x00\x01\xe2+\xef\x0f\x00\x00\x00\x00IEND\xaeB`\x82'

try:
    s3.put_object(
        Bucket=S3_BUCKET,
        Key=TEST_KEY,
        Body=DUMMY_PNG,
        ContentType="image/png"
    )
    url = f"{S3_ENDPOINT}/{S3_BUCKET}/{TEST_KEY}"
    print(f"✅ Uploaded test image. Open this URL in your browser to verify it previews instead of downloading:")
    print(f"   {url}")
except Exception as e:
    print(f"❌ Upload failed: {e}")
