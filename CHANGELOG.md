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

- SAML logout requests are accepted on the HTTP-POST binding as well as
  HTTP-Redirect, and the federation metadata lists both. The answer goes to the
  registered Logout URL over the binding the request used, signed inside when
  posted. A logout request marked asynchronous (the SAML Asynchronous Single
  Logout extension) gets no answer; the browser is shown the outcome.

- **Upload metadata file** under Basic SAML Configuration, as in Entra: the
  application's entity ID, its HTTP-POST Reply URLs with their indexes and
  default, and a compatible Logout URL fill in the form for review. Nothing is saved
  until the administrator saves it.
- The metadata file upload takes this application's entry from a file grouping
  several (by its Identifier), accepts files up to 2 MB, and refuses metadata
  that has expired, lists one entity twice, or puts a SAML element inside
  `Extensions`.
- Reply URLs keep an explicit index and default. A line in the Reply URL box
  may end with `index=N` and `default`; plain lines work as before.

- **Choose how SAML assertions are encrypted**: AES-256-GCM, AES-128-GCM or
  AES-256-CBC, with the key wrapped by RSA-OAEP (XML Encryption 1.1) or
  RSA-OAEP-MGF1P over SHA-256 or SHA-1. Applications already set up keep
  AES-256-CBC with RSA-OAEP-MGF1P over SHA-1, as Entra sends; newly set up ones
  start with AES-256-GCM and RSA-OAEP over SHA-256. The encryption certificate
  no longer has to be pasted again to change the method, and "Stop encrypting"
  is its own button.

- A persistent SAML Name ID is always the application's own pairwise
  identifier, whatever the Name ID source; a new source, *user.pairwiseid
  (lowercase hex)*, gives it in lowercase for an application that ignores case.
- SAML federation metadata declares the signing and digest algorithms each
  application uses (SAML Metadata Profile for Algorithm Support).

- Signed SAML requests may use ECDSA: ECDSA-SHA256 with a P-256 key or
  ECDSA-SHA384 with a P-384 key, on both bindings, besides RSA-SHA256. A
  verification certificate may hold such an EC key. The federation metadata
  lists both among its signing methods. Entra verifies RSA only.
- A metadata file's signing certificates are offered under Verification
  certificates, each with its own Add; none is trusted until an administrator
  adds it. Entra takes no keys from an uploaded file.
- A SAML verification certificate is used for its key alone, as the SAML
  Metadata Interoperability Profile requires: an expired or not-yet-valid
  certificate can be added and its key verifies until it is removed. The
  console marks an expired one.
- A SAML Identifier (Entity ID) may be up to 1024 characters, as SAML allows
  (it was 512). Existing Unicode identifiers continue to work.

- **My Account has tabs**: My apps, Profile and Security, each at its own
  address. My apps is where the page opens.
- **Application logos**: on an application's Overview, upload a logo (PNG, JPEG
  or BMP up to 100 KB, as in Entra) or choose one of sixteen built-in icons.
  My apps shows each application as a tile with its logo, or its initials, and
  the whole tile opens it.

### Fixed

- A user not assigned to an application that requires assignment (OIDC, SAML
  or device code) is now told so plainly. The page gives Entra's full
  AADSTS50105 text, naming the application, its ID and the signed-in account
  and saying to ask an administrator for access. It used to be a shortened
  line in small grey type, run together with the trace and correlation IDs.
  Every sign-in error page now shows the reason first, in normal type, with
  the IDs under "Troubleshooting details", as Entra's does.
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
- SAML error responses are now signed with the application's signing
  certificate, so the application can trust the status they carry.
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
