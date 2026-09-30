# OpenID Foundation conformance suite

Results, accepted deviations and open gaps: `docs/conformance.md`.

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
(`RUST_OIDC_HOST_IP`, default `host-gateway`).

Under rootless podman the container cannot reach the host's own LAN IP -- the
connection is refused even with no firewall, because the container's netns only
reaches the host through the host-gateway address (`host.containers.internal`,
169.254.1.2). `host-gateway` is therefore the right default. Override
`RUST_OIDC_HOST_IP` with a real IP only when rust-oidc runs on a different host.
Symptom if this is wrong: every test module goes INTERRUPTED and the server log
shows `GetDynamicServerConfiguration: ... Connection refused`.

Recreate the stack with `podman-compose -p oidf down && podman-compose -p oidf up -d`;
`--force-recreate server` fails because nginx depends on it, and leaves the old
container (and its old env) in place.
