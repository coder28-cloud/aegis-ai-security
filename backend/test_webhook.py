"""
Scratch script — sends a real, properly-signed webhook request to your
own running server, simulating what GitHub itself would send. Not
part of the app; safe to delete after testing.
"""
import hashlib
import hmac
import json
import urllib.request

from app.config import settings

payload = {
    "repository": {"full_name": "coder28-cloud/aegis-ai-security"},
    "after": "6a30d55dd9bed40327163e8970027f409f8eb05c",
}
payload_bytes = json.dumps(payload).encode()

secret = settings.GITHUB_WEBHOOK_SECRET.get_secret_value()
signature = "sha256=" + hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()

req = urllib.request.Request(
    "http://127.0.0.1:8000/api/v1/webhooks/github",
    data=payload_bytes,
    method="POST",
    headers={
        "Content-Type": "application/json",
        "X-Hub-Signature-256": signature,
    },
)

with urllib.request.urlopen(req) as response:
    print(response.status, response.read().decode())