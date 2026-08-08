# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-07

Initial release.

`agentic-password-injector` is a self-hosted MCP server that logs an agent
into a website by injecting a credential straight into the page's DOM over
CDP, so the model never sees the secret.

### Added

- Four MCP tools: `list_credentials`, `fill_credential`, `login`, and
  `fill_totp`.
- Two vault backends: Arc's own credential store and the macOS Keychain
  (`security` CLI).
- Security model: the secret never crosses the tool boundary (every return
  type is `{ filled, submitted?, reason? }`, no reveal path exists); the
  credential's origin is matched against the tab's live origin *before* the
  consent dialog is even raised; that origin (plus the frame's `loaderId`) is
  re-asserted immediately before every keystroke to close the TOCTOU window a
  60-second consent prompt leaves open; and each fill is gated behind a
  per-use native macOS Allow/Deny dialog showing the bound host and username,
  defaulting to Deny.
