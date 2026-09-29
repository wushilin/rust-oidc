// Application (service-to-service) authentication with MSAL Node.
//
// Same checks as the MSAL Python test: client_credentials with a secret and a
// `.default` scope, then validate the token like a resource API would.
// TLS trust for the dev certificate comes from NODE_EXTRA_CA_CERTS (set by run.sh).

import { ConfidentialClientApplication, LogLevel } from "@azure/msal-node";
import { createRemoteJWKSet, jwtVerify } from "jose";

const env = (name) => {
  const v = process.env[name];
  if (!v) throw new Error(`missing env ${name}`);
  return v;
};
const BASE = env("RUST_OIDC_BASE");
const TENANT_ID = env("TENANT_ID");
const TENANT_DOMAIN = env("TENANT_DOMAIN");
const API_APP_ID = env("API_APP_ID");
const CLIENT_ID = env("CLIENT_APP_ID");
const CLIENT_SECRET = env("CLIENT_SECRET");
const EXPECTED_ROLES = env("EXPECTED_ROLES").split(",").sort();
const SCOPES = [`api://${API_APP_ID}/.default`];
const HOST = new URL(BASE).host;

const failures = [];
const check = (name, cond, detail) => {
  console.log(`${cond ? "PASS" : "FAIL"} ${name}${cond ? "" : `: ${JSON.stringify(detail)}`}`);
  if (!cond) failures.push(name);
};

const entraStyle = (authority, secret = CLIENT_SECRET) =>
  new ConfidentialClientApplication({
    auth: {
      clientId: CLIENT_ID,
      clientSecret: secret,
      authority,
      // Trust this host instead of asking login.microsoftonline.com.
      knownAuthorities: [HOST],
    },
    system: { loggerOptions: { logLevel: LogLevel.Error, loggerCallback: () => {} } },
  });

async function validate(token) {
  const config = await (await fetch(`${BASE}/${TENANT_ID}/v2.0/.well-known/openid-configuration`)).json();
  const jwks = createRemoteJWKSet(new URL(config.jwks_uri));
  const { payload, protectedHeader } = await jwtVerify(token, jwks, {
    issuer: config.issuer,
    audience: API_APP_ID,
    algorithms: ["RS256"],
  });
  return { payload, protectedHeader };
}

async function expectError(promise) {
  try {
    await promise;
    return null;
  } catch (e) {
    return e;
  }
}

// 1. Entra-style authority, tenant by GUID.
{
  const app = entraStyle(`${BASE}/${TENANT_ID}`);
  const result = await app.acquireTokenByClientCredential({ scopes: SCOPES });
  check("entra authority (GUID): token issued", !!result?.accessToken, result);
  const { payload, protectedHeader } = await validate(result.accessToken);
  check("header: kid == x5t", protectedHeader.kid === protectedHeader.x5t, protectedHeader);
  check("token: aud", payload.aud === API_APP_ID, payload);
  check("token: azp", payload.azp === CLIENT_ID, payload);
  check("token: tid", payload.tid === TENANT_ID, payload);
  check("token: idtyp app", payload.idtyp === "app", payload);
  check("token: roles", JSON.stringify([...(payload.roles ?? [])].sort()) === JSON.stringify(EXPECTED_ROLES), payload);

  const again = await app.acquireTokenByClientCredential({ scopes: SCOPES });
  check("msal: second call served from cache", again.fromCache === true && again.accessToken === result.accessToken, again.fromCache);
}

// 2. Entra-style authority, tenant by verified domain.
{
  const result = await entraStyle(`${BASE}/${TENANT_DOMAIN}`).acquireTokenByClientCredential({ scopes: SCOPES });
  check("entra authority (domain): token issued", !!result?.accessToken, result);
}

// 3. Generic OIDC protocol mode, authority = issuer.
{
  const app = new ConfidentialClientApplication({
    auth: {
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      authority: `${BASE}/${TENANT_ID}/v2.0`,
      knownAuthorities: [HOST],
      protocolMode: "OIDC",
    },
    system: { loggerOptions: { logLevel: LogLevel.Error, loggerCallback: () => {} } },
  });
  const result = await app.acquireTokenByClientCredential({ scopes: SCOPES });
  check("protocolMode OIDC: token issued", !!result?.accessToken, result);
}

// 4. Error surface.
{
  const err = await expectError(
    entraStyle(`${BASE}/${TENANT_ID}`, "wrong").acquireTokenByClientCredential({ scopes: SCOPES }),
  );
  check("bad secret: invalid_client", err?.errorCode === "invalid_client", err?.errorCode);
  check("bad secret: AADSTS7000215", err?.errorMessage?.startsWith("7000215") || err?.errorMessage?.includes("AADSTS7000215"), err?.errorMessage);

  const err2 = await expectError(
    entraStyle(`${BASE}/${TENANT_ID}`).acquireTokenByClientCredential({ scopes: ["api://nope/.default"] }),
  );
  check("unknown resource: AADSTS500011", err2?.errorMessage?.includes("AADSTS500011"), err2?.errorMessage);
}

if (failures.length) {
  console.log(`\n${failures.length} check(s) failed`);
  process.exit(1);
}
console.log("\nall MSAL Node checks passed");
