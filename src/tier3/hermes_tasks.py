"""
tier3/hermes_tasks.py — Browser task payload builders for Tier 3 escalation.

Constructs structured task payloads for common auth-detection scenarios that
require browser-level inspection via Hermes Agent.

Supported task scenarios:
  - SPA shell detection (root HTML is <div id="root"></div> or equivalent)
  - JS-rendered auth wall (page looks open via HTTP but gated after JS runs)
  - Modal login detection (login form appears only after CTA interaction)
  - Cookie / session-gated page verification
  - Client-side redirect interception (200 OK → JS redirect to /login)
  - Admin / dashboard area verification
  - GraphQL playground detection in browser

Each task payload should capture:
  - Screenshot evidence (uploaded to S3 when configured)
  - Final URL after JS execution
  - Any visible auth-related DOM elements
  - Interaction steps performed

This module must NOT make any network calls. It only builds dict payloads.
"""

from __future__ import annotations


def build_auth_check_task(domain: str, escalation_reason: str, tier2_output: dict) -> dict:
    """
    Build a generic browser auth-check task payload for a domain.

    Args:
        domain:            The domain to inspect.
        escalation_reason: Human-readable reason from Tier 2 output.
        tier2_output:      Full Tier 2 result dict for context.

    Returns:
        A Hermes task payload dict ready to submit via ``HermesClient``.
        Includes ``_s3_instructions`` when S3 is configured in settings.
    """
    from config import settings

    # Prefer https, but let Hermes handle redirects
    target_url = f"https://{domain}"

    # Give Hermes a clear instruction based on the LLM's reason
    instruction = (
        f"Determine if this service requires authentication. "
        f"Context from static analysis: {escalation_reason}. "
        f"Please check if the root page is an SPA shell that loads a login form, "
        f"or if clicking primary CTA buttons reveals an auth wall."
    )

    payload: dict = {
        "domain": domain,
        "url": target_url,
        "instructions": instruction,
        "context": {
            "tier1_verdict": tier2_output.get("verdict", "UNKNOWN"),
            "service_type": tier2_output.get("service_type", "UNKNOWN"),
        },
    }

    # Inject S3 upload instructions when credentials are configured
    if settings.s3_enabled:
        payload["_s3_instructions"] = _build_s3_instruction(domain, settings)

    return payload


def _build_s3_instruction(domain: str, settings) -> str:
    """
    Build the S3 upload instruction block injected into the Hermes user message.

    Single execute_code block approach:
    - Uses file mtime to upload only screenshots from the last 10 minutes
    - Avoids needing a separate pre-task cleanup step (which doubled agent output)
    - Date computed on Hermes server side to avoid UTC rollover mismatch
    """
    s3_prefix_base = f"{settings.s3_screenshot_prefix}/{domain}"
    public_base = f"{settings.s3_endpoint}/{settings.s3_bucket}/{s3_prefix_base}"

    return f"""\
SCREENSHOT UPLOAD:
After completing your investigation, run this code with execute_code to upload screenshots:

```python
import boto3, os, datetime

# CRITICAL: You MUST replace the placeholder string below with the actual absolute path to your screenshot!
screenshots_to_upload = [
    "REPLACE_ME_WITH_SCREENSHOT_PATH"
]

if "REPLACE_ME_WITH_SCREENSHOT_PATH" in screenshots_to_upload:
    raise ValueError("AGENT ERROR: You forgot to put the screenshot path in the array! Edit the code and try again.")

s3 = boto3.client("s3", endpoint_url="{settings.s3_endpoint}", aws_access_key_id="{settings.s3_access_key}", aws_secret_access_key="{settings.s3_secret_key}", region_name="us-east-1")
u = []
for p in screenshots_to_upload:
    if not os.path.exists(p): continue
    k = f"{s3_prefix_base}/{{datetime.date.today().isoformat()}}/{{os.path.basename(p)}}"
    try: s3.upload_file(p, "{settings.s3_bucket}", k, ExtraArgs={{"ContentType": "image/png"}}); u.append(f"{settings.s3_endpoint}/{settings.s3_bucket}/{{k}}"); os.remove(p)
    except: u.append(os.path.basename(p))
print("SCREENSHOT_URLS:", u)
```

Put the S3 URLs from the output into the screenshots array. \
Example URL: {public_base}/YYYY-MM-DD/browser_screenshot_<hash>.png
"""

