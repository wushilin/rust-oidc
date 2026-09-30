"""A scripted browser for the container relying-party suites (stdlib only).

Follows redirects by hand so callers can see every hop, keeps cookies, trusts
only the dev CA, and submits rust-oidc's login form when it meets it.
"""

import html
import http.cookiejar
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _field(page, name):
    m = re.search(rf'name="{name}" value="([^"]*)"', page)
    return html.unescape(m.group(1)) if m else None


class Browser:
    def __init__(self, ca_file):
        ctx = ssl.create_default_context(cafile=ca_file)
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(self.jar),
            _NoRedirect(),
        )

    def request(self, url, data=None, headers=None):
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request(url, data=body, headers=headers or {})
        try:
            resp = self.opener.open(req, timeout=30)
        except urllib.error.HTTPError as e:
            resp = e
        return resp.status, dict(resp.headers.items()), resp.read().decode("utf-8", "replace")

    def sign_in(self, url, upn, password, max_hops=15):
        """Follow `url` through redirects, filling in rust-oidc's login form.

        Returns (status, final_url, body, hops) where hops lists every URL visited.
        """
        hops, data, submitted = [], None, False
        for _ in range(max_hops):
            hops.append(url)
            status, headers, body = self.request(url, data)
            data = None
            if status in (301, 302, 303, 307, 308):
                loc = {k.lower(): v for k, v in headers.items()}.get("location")
                if loc is None:
                    raise RuntimeError(f"{status} without Location from {url}: {headers}")
                url = urllib.parse.urljoin(url, loc)
                continue
            if status == 200 and 'name="csrf"' in body and not submitted:
                submitted = True
                action = re.search(r'action="([^"]+)"', body)
                url = urllib.parse.urljoin(url, html.unescape(action.group(1))) if action else url
                data = {
                    "csrf": _field(body, "csrf"),
                    "request": _field(body, "request"),
                    "op": "login",
                    "upn": upn,
                    "password": password,
                }
                continue
            return status, url, body, hops
        raise RuntimeError(f"too many redirects: {hops}")
