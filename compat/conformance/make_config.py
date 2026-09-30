"""Build the conformance-suite plan config for rust-oidc from a fixture file.

fixture (created on the server, never committed):
  {"tenantId", "upn", "password", "client1": {"id","secret"}, "client2": {...}}
"""
import json
import sys

fx = json.load(open(sys.argv[1]))
base = sys.argv[2] if len(sys.argv) > 2 else "https://gate.wushilin.net:9443/rust-oidc"
authorize = f"{base}/*/oauth2/v2.0/authorize*"
login_post = f"{base}/*/login*"


def login_task(placeholder=None):
    commands = []
    if placeholder:
        commands.append(["wait", "xpath", "//*", 10, "Sign in", placeholder])
    commands += [
        ["text", "name", "upn", fx["upn"], "optional"],
        ["text", "name", "password", fx["password"], "optional"],
        ["click", "xpath", "//button[@type='submit']", "optional"],
    ]
    return {"task": "Login", "optional": True, "match": authorize, "commands": commands}


verify = {"task": "Verify Complete", "match": "*/test/*/callback*",
          "commands": [["wait", "id", "submission_complete", 10]]}


def flow(placeholder=None):
    return [{"match": authorize, "tasks": [login_task(placeholder), verify]}]


error_page = [{
    "comment": "expect an error page, not a redirect",
    "match": authorize,
    "tasks": [{"task": "Expect error page", "match": authorize,
               "commands": [["wait", "xpath", "//*", 10, "trouble signing you in", "update-image-placeholder"]]}],
}]

logout = [{
    "match": f"{base}/*/oauth2/v2.0/logout*",
    "tasks": [{"task": "Logout", "optional": True, "match": f"{base}/*/oauth2/v2.0/logout*",
               "commands": [["wait", "xpath", "//*", 10, "signed out", "update-image-placeholder-optional"]]},
              {"task": "Verify Complete", "optional": True, "match": "*/test/*/post*"}],
}]

config = {
    "alias": "rust-oidc",
    "description": "rust-oidc (Entra ID v2 compatible)",
    "server": {"discoveryUrl": f"{base}/{fx['tenantId']}/v2.0/.well-known/openid-configuration"},
    "client": {"client_id": fx["client1"]["id"], "client_secret": fx["client1"]["secret"]},
    "client2": {"client_id": fx["client2"]["id"], "client_secret": fx["client2"]["secret"]},
    # The basic/formpost certification plans run one module per client-auth method and
    # OIDCCServerTestClientSecretPost overwrites config.client with config.client_secret_post,
    # so the key must exist or the module dies at GetStaticClientConfiguration before it ever
    # reaches the server. rust-oidc accepts either method on any confidential client (as Entra
    # does), so client1 can serve both.
    "client_secret_post": {"client_id": fx["client1"]["id"], "client_secret": fx["client1"]["secret"]},
    "browser": flow() + logout,
    "override": {
        "oidcc-prompt-login": {"browser": flow("update-image-placeholder-optional")},
        "oidcc-max-age-1": {"browser": flow("update-image-placeholder-optional")},
        "oidcc-ensure-registered-redirect-uri": {"browser": error_page},
        "oidcc-redirect-uri-query-added": {"browser": error_page},
        "oidcc-redirect-uri-query-mismatch": {"browser": error_page},
        "oidcc-ensure-redirect-uri-in-authorization-request": {"browser": error_page},
    },
}
json.dump(config, sys.stdout, indent=1)
