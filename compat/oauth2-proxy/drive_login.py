"""Drive an oauth2-proxy OIDC login against rust-oidc and report each step as JSON.

usage: drive_login.py <proxy-base-url> <upn>
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
from browser import Browser  # noqa: E402

base = sys.argv[1].rstrip("/")
upn = sys.argv[2]
b = Browser(os.environ["CA_FILE"])

# 1. Unauthenticated request to the protected upstream: do not follow.
s1, h1, _ = b.request(f"{base}/protected")
h1 = {k.lower(): v for k, v in h1.items()}
# The redirect target: oauth2-proxy's own start endpoint, which sends the browser on
# to the identity provider.
s1b, h1b, _ = b.request(f"{base}/oauth2/start?rd=/protected")
h1b = {k.lower(): v for k, v in h1b.items()}

# 2. Full login: /oauth2/start -> rust-oidc authorize -> login form -> callback.
s2, url2, body2, hops = b.sign_in(f"{base}/oauth2/start?rd=/protected", upn, os.environ["USER_PASSWORD"])

# 3. Session cookie now grants access to the upstream.
s3, _h3, body3 = b.request(f"{base}/protected")
try:
    echoed = json.loads(body3)
except ValueError:
    echoed = None

# 4. /oauth2/userinfo shows what oauth2-proxy extracted from the session.
s4, _h4, body4 = b.request(f"{base}/oauth2/userinfo")
print(json.dumps({
    "unauth": {"status": s1, "location": h1.get("location"),
              "start_status": s1b, "start_location": h1b.get("location")},
    "login": {"status": s2, "final_url": url2, "hops": hops, "body_head": body2[:300]},
    "protected": {"status": s3, "echo": echoed},
    "userinfo": {"status": s4, "body": body4[:500]},
}))
