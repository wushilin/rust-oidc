# OpenID Foundation conformance suite

Runs the official OIDF conformance suite (prebuilt images, dev mode) against a
deployed rust-oidc using podman.

Setup on the test host (done on titanl):

1. `git clone --depth 1 https://gitlab.com/openid/conformance-suite ~/conformance-suite`
   (only its `scripts/` are used, for the plan runner).
2. Create a fixture on the rust-oidc server: a tenant, a user and two web clients
   whose redirect URIs are `https://localhost.emobix.co.uk:8443/test/a/rust-oidc/callback`
   and `.../post_logout_redirect`. Save it as `~/conformance-suite/rust-oidc-fixture.json`:
   `{"tenantId", "upn", "password", "client1": {"id", "secret"}, "client2": {...}}`
   (never commit it).
3. `compat/conformance/run.sh` runs the basic, config and form_post certification
   plans. Results (HTML/JSON exports) land in `~/.cache/rust-oidc-conformance/results`.
   The suite UI is at https://<host>:18443/.

The server container resolves `gate.wushilin.net` to the host running rust-oidc
(`RUST_OIDC_HOST_IP`, default 192.168.44.113).
