# Changelog

Notable changes to rust-oidc. Releases before 0.6.0 are described on their
[GitHub release pages](https://github.com/wushilin/rust-oidc/releases).

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
