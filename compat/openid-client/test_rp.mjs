// Generic OIDC relying party: openid-client (OpenID Certified RP library).
//
// Uses only standard OIDC — discovery from the issuer, authorization code +
// PKCE, strict ID token validation (iss, aud, nonce, exp, auth_time with
// max_age), UserInfo with subject check, refresh, form_post and RP-initiated
// logout — against rust-oidc with no Entra-specific configuration.

import * as client from "openid-client";

const env = (n) => process.env[n] ?? (() => { throw new Error(`missing env ${n}`); })();
const BASE = env("RUST_OIDC_BASE");
const TENANT_ID = env("TENANT_ID");
const CLIENT_ID = env("WEB_APP_ID");
const SECRET = env("WEB_SECRET");
const REDIRECT_URI = env("WEB_REDIRECT_URI");
const UPN = env("USER_UPN");
const PASSWORD = env("USER_PASSWORD");

const failures = [];
const check = (name, cond, detail) => {
  console.log(`${cond ? "PASS" : "FAIL"} ${name}${cond ? "" : `: ${JSON.stringify(detail)}`}`);
  if (!cond) failures.push(name);
};

// ---- a minimal browser: cookie jar + manual redirects ----
const jar = new Map();
const cookieHeader = () => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
const remember = (resp) => {
  for (const c of resp.headers.getSetCookie()) {
    const [pair] = c.split(";");
    const i = pair.indexOf("=");
    const [k, v] = [pair.slice(0, i), pair.slice(i + 1)];
    if (v === "" || /max-age=0/i.test(c)) jar.delete(k);
    else jar.set(k, v);
  }
};
const unescape = (s) =>
  s.replaceAll("&quot;", '"').replaceAll("&#x27;", "'").replaceAll("&lt;", "<").replaceAll("&gt;", ">").replaceAll("&amp;", "&");
const field = (html, name) => {
  const m = html.match(new RegExp(`name="${name}" value="([^"]*)"`));
  return m ? unescape(m[1]) : undefined;
};

async function browse(url, init = {}) {
  const resp = await fetch(url, { ...init, redirect: "manual", headers: { ...(init.headers ?? {}), cookie: cookieHeader() } });
  remember(resp);
  return resp;
}

/** Visit the authorize URL, sign in if asked, return the final response. */
async function signIn(authUrl) {
  let resp = await browse(authUrl);
  if (resp.status === 200) {
    const html = await resp.text();
    if (field(html, "op") === "login") {
      const action = unescape(html.match(/action="([^"]+)"/)[1]);
      resp = await browse(action, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          csrf: field(html, "csrf"), request: field(html, "request"), op: "login", upn: UPN, password: PASSWORD,
        }),
      });
    } else {
      return { resp, html };
    }
  }
  return { resp, html: resp.status === 200 ? await resp.text() : "" };
}

// ---- discovery straight from the issuer ----
const issuer = new URL(`${BASE}/${TENANT_ID}/v2.0`);
const config = await client.discovery(issuer, CLIENT_ID, undefined, client.ClientSecretPost(SECRET));
check("discovery: issuer", config.serverMetadata().issuer === issuer.href, config.serverMetadata().issuer);

// ---- authorization code + PKCE + nonce + max_age ----
const verifier = client.randomPKCECodeVerifier();
const nonce = client.randomNonce();
const state = client.randomState();
const authUrl = client.buildAuthorizationUrl(config, {
  redirect_uri: REDIRECT_URI,
  scope: "openid profile email offline_access",
  code_challenge: await client.calculatePKCECodeChallenge(verifier),
  code_challenge_method: "S256",
  nonce,
  state,
  max_age: "3600",
});
const { resp } = await signIn(authUrl);
check("authorize: redirect after sign-in", resp.status === 302, resp.status);
const callback = new URL(resp.headers.get("location"));
const tokens = await client.authorizationCodeGrant(
  config,
  callback,
  { pkceCodeVerifier: verifier, expectedNonce: nonce, expectedState: state, maxAge: 3600 },
  { redirect_uri: REDIRECT_URI },
);
const claims = tokens.claims();
check("id token validated (iss/aud/nonce/exp/auth_time)", !!claims?.sub, claims);
check("id token: oid present", typeof claims?.oid === "string", claims);
check("refresh token issued", typeof tokens.refresh_token === "string", Object.keys(tokens));

// ---- UserInfo with subject check ----
const info = await client.fetchUserInfo(config, tokens.access_token, claims.sub);
check("userinfo: sub matches", info.sub === claims.sub, info);
check("userinfo: email", typeof info.email === "string", info);

// ---- refresh ----
const refreshed = await client.refreshTokenGrant(config, tokens.refresh_token);
check("refresh: new access token", refreshed.access_token && refreshed.access_token !== tokens.access_token);
check("refresh: rotated refresh token", refreshed.refresh_token && refreshed.refresh_token !== tokens.refresh_token);
check("refresh: id token same sub", refreshed.claims()?.sub === claims.sub, refreshed.claims());
let reuseRejected = false;
try {
  await client.refreshTokenGrant(config, tokens.refresh_token);
} catch (e) {
  reuseRejected = e.error === "invalid_grant";
}
check("refresh: replayed token rejected", reuseRejected);

// ---- form_post response mode (SSO, so no login form) ----
{
  const v = client.randomPKCECodeVerifier();
  const n = client.randomNonce();
  const url = client.buildAuthorizationUrl(config, {
    redirect_uri: REDIRECT_URI,
    scope: "openid",
    response_mode: "form_post",
    code_challenge: await client.calculatePKCECodeChallenge(v),
    code_challenge_method: "S256",
    nonce: n,
  });
  const { resp, html } = await signIn(url);
  check("form_post: auto-submit page", resp.status === 200 && html.includes('name="hiddenform"'), resp.status);
  const code = field(html, "code");
  const request = new Request(REDIRECT_URI, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ code }),
  });
  const t = await client.authorizationCodeGrant(config, request, { pkceCodeVerifier: v, expectedNonce: n }, { redirect_uri: REDIRECT_URI });
  check("form_post: code redeemed", t.claims()?.sub === claims.sub);
}

// ---- RP-initiated logout ----
{
  const url = client.buildEndSessionUrl(config, {
    post_logout_redirect_uri: REDIRECT_URI,
    id_token_hint: tokens.id_token,
    state: "bye",
  });
  const resp = await browse(url);
  check("logout: redirect to registered URI", resp.status === 302 && resp.headers.get("location").startsWith(REDIRECT_URI), resp.status);
  const after = await browse(client.buildAuthorizationUrl(config, { redirect_uri: REDIRECT_URI, scope: "openid", prompt: "none" }));
  const err = new URL(after.headers.get("location")).searchParams.get("error");
  check("logout: session ended (prompt=none -> login_required)", err === "login_required", err);
}

if (failures.length) {
  console.log(`\n${failures.length} check(s) failed`);
  process.exit(1);
}
console.log("\nall openid-client checks passed");
