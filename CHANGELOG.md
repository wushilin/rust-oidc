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
- Signed SAML requests are verified on the HTTP-POST binding as well as
  HTTP-Redirect. An invalid signature is refused whenever the application has a
  verification certificate, even if it does not require signatures.

### Fixed

- A SAML request for an authentication context declaration, which is not
  supported, is now refused with `NoAuthnContext` instead of signing in. An
  unmet authentication context is reported with the top-level status `Responder`.
- A SAML sign-in or logout request whose `Destination` names another endpoint is
  now discarded even when unsigned, as SAML Core 3.2.1 requires.
- A well-formed SAML request that cannot be honored (a `Subject`, an unsupported
  response binding, NameID format or context comparison) now gets a SAML error
  at the registered Reply URL instead of a local error page.
- A SAML request of another protocol version is answered with the top-level
  status `VersionMismatch` (`RequestVersionTooLow` or `RequestVersionTooHigh`),
  and one with both `ForceAuthn` and `IsPassive` with `NoPassive`, both at the
  registered Reply URL. Both used to get a local error page. A request whose
  `IssueInstant` is missing or not a valid time now gets `Requester` there too,
  signed or not; an invalid one used to be ignored, or reported as expired when
  signed.
- An encrypted SAML assertion now always comes in a signed `Response`, whatever
  the signing option, and its encrypted key names the application as `Recipient`.

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
