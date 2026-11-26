# Changelog

Notable changes to rust-oidc. Releases before 0.6.0 are described on their
[GitHub release pages](https://github.com/wushilin/rust-oidc/releases).

## Unreleased

### Added

- SAML 2.0 single sign-on for applications, following Entra's setup: create an
  application by name, choose SAML under Single sign-on, then set Basic SAML
  Configuration, Attributes & Claims and SAML Certificates. Includes SP- and
  IdP-initiated sign-in, signed request verification (HTTP-Redirect), assertion
  encryption, certificate rollover, federation metadata and Single Logout.
- **My apps** on My Account: the applications a user is assigned to, directly or
  through a group, ready to open.

### Fixed

- A SAML request for an authentication context declaration, which is not
  supported, is now refused with `NoAuthnContext` instead of signing in. An
  unmet authentication context is reported with the top-level status `Responder`.

### Security

- A second sign-in step now belongs to the authorization request it began with,
  so it cannot complete a different request, such as one asking for a fresh
  sign-in.

## 0.6.0

### Fixed

- Signing in from Chrome ended on a blank page for the ordinary (`query` and
  `fragment`) response modes: Chrome applies the Content-Security-Policy
  `form-action` directive to the redirect that follows a form submission, and
  the sign-in pages only allowed `'self'`, so the 302 to the client's redirect
  URI was dropped. Submitting again then reported an expired session, and
  reloading the authorize URL went through. The login, second-step,
  "set up an authenticator?", change-password, consent and account-picker
  pages now list the origin of the validated redirect URI beside `'self'`.
  Firefox and Safari were never affected. Admin console pages, the device
  flow and My Account are unchanged.
