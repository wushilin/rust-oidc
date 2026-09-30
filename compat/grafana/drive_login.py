"""Drive a Grafana generic-OAuth login against rust-oidc and report the outcome.

usage: drive_login.py <grafana-base-url>
Prints one JSON object: {"user": {...}|null, "api_status": int, "hops": [...]}.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
from browser import Browser  # noqa: E402

base = sys.argv[1].rstrip("/")
b = Browser(os.environ["CA_FILE"])
status, url, _body, hops = b.sign_in(
    f"{base}/login/generic_oauth", os.environ["USER_UPN"], os.environ["USER_PASSWORD"]
)
api_status, _h, api_body = b.request(f"{base}/api/user", headers={"Accept": "application/json"})
user = json.loads(api_body) if api_status == 200 else None
print(json.dumps({"final_status": status, "final_url": url, "api_status": api_status, "user": user, "hops": hops}))
