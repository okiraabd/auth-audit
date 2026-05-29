"""
Probe Hermes agent for its available capabilities:
- What tools does it have?
- Can it execute Python code?
- Is boto3/aws available?
- Can it access the local filesystem?
- Can it use curl/wget?
"""

import asyncio
import httpx
import json

HERMES_URL = "http://192.168.24.29:8643/v1/chat/completions"
HERMES_KEY = "Rahasia2026"

CAPABILITY_PROBE = """I need to understand what capabilities you have available to me as an agent.

Please answer each of these questions honestly — if you don't have a capability, just say "no":

1. TOOL LIST: What tools/functions can you call? List them all (e.g. browser_navigate, code_execute, take_screenshot, etc.)

2. CODE EXECUTION: Can you run Python code? If yes, can you do: `import boto3`?

3. FILE SYSTEM: Can you read/write files on the server where you are running?

4. SCREENSHOT PATH: When you take a screenshot with your browser tool, where is the file saved on disk? What is the full path?

5. CURL/WGET: Can you run shell commands like `curl` or `aws s3 cp`?

6. S3 UPLOAD: Given a screenshot file at a local path, what is the BEST way you can upload it to an S3-compatible endpoint (http://192.168.180.99:8000)?

Answer each numbered question directly. Be specific and technical."""


async def probe_hermes():
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {HERMES_KEY}",
    }
    payload = {
        "model": "hermes",
        "messages": [
            {"role": "user", "content": CAPABILITY_PROBE}
        ],
        "max_tokens": 2048,
        "temperature": 0.1,
        "stream": False,
    }

    async with httpx.AsyncClient(timeout=httpx.Timeout(120.0), verify=False) as client:
        print("Sending capability probe to Hermes...")
        response = await client.post(HERMES_URL, json=payload, headers=headers)
        print(f"Status: {response.status_code}")
        data = response.json()
        content = data["choices"][0]["message"]["content"]
        print("\n" + "="*60)
        print("HERMES CAPABILITY RESPONSE:")
        print("="*60)
        print(content)
        print("="*60)
        return content


if __name__ == "__main__":
    asyncio.run(probe_hermes())
