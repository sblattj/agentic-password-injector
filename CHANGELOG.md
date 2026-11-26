# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `apinj-accounts`, an account manager for CLI tools that have one login per
  HOME (Kiro CLI first), modeled on macsub's verbs: `add`, `ls`, `usage`,
  `swap` / `best`, `home`, `data-dir`, `run`, `whoami`, `login`, `shim`, `rm`.
  - Each account runs under its own HOME, so a second login works without
    logging the first one out. A `--pinned` account (the login you already use)
    is never logged in, logged out or written to, and no other account may
    share its HOME.
  - `login` runs the device-code flow and approves it in the account's own
    headless browser profile (its own cookies, a DevTools port the browser
    picks), typing the username, password and optional TOTP through the
    injector's gated fills. The password is typed at most once per run, it only
    clicks allowlisted buttons on the two expected origins, and a login that
    lands as the wrong identity is logged back out.
  - `usage` reads credits used and left per account from `/usage`; `best`
    picks the account with the most left.
  - `APINJ_ACCOUNT=<name>` selects the account per process, so a harness can
    pick one per run (`home`, `data-dir`, `run`, and the `shim` wrapper).
  - The registry (`~/.config/apinj-accounts/accounts.json`, 0600) holds no
    secrets; passwords stay in the Keychain as `apinj:<entry>`.

## [0.7.0] - 2026-11-20

### Fixed

- The consent dialog no longer outlives MCP gateway timeouts, and no longer
  blocks the server while it is open. Fixes #1.
  - Allow/Deny dialogs give up after 25 s by default (was 60 s), below the
    ~30 s many gateways allow a tool call. `APINJ_CONSENT_TIMEOUT_S` (1 to 600)
    changes it. An unanswered dialog now returns `consent_timeout` instead of
    `user_denied`.
  - `osascript` runs async, so `tools/list` and health checks are answered
    while a dialog is up. Before, `execFileSync` froze the event loop and a
    gateway could mark the backend unhealthy.
  - A cancelled or disconnected call kills its dialog, and an Allow that
    arrives after the caller has gone types nothing (`request_cancelled`).
    Before, a late Allow still typed into the page with nobody listening for
    the result; the new end-to-end test reproduced that silent fill.
  - The post-consent wait in `fill_sms_code`, `fill_email_code` and the
    passkey tools shares one time budget with the dialog, so a slow Allow plus
    a full wait cannot outlive the gateway either.

## [0.6.0] - 2026-11-20

### Added

- Named CDP endpoints: fill into more than one browser. `CDP_ENDPOINTS`
  (`name=url,...`, cdp-toolkit's syntax) names extra DevTools ports, and a
  `tabId` of `endpoint:<name>/<targetId>` targets a tab there. A bare id still
  means the `CDP_BASE` browser and is never searched for elsewhere. An endpoint
  marked `?mode=read` refuses every fill with `endpoint_read_only`; an unknown
  name is `unknown_endpoint`; a malformed value is `endpoint_config_error`. All
  three are decided before the vault is read. The origin gate, consent,
  loaderId guard and visibility checks run unchanged on every endpoint.
  Fixes #4.

## [0.5.0] - 2026-11-20

### Added

- `passkey_register` and `passkey_login`: agent passkeys through the CDP
  `WebAuthn` domain. A virtual authenticator (CTAP2, internal, resident key,
  user verification) is attached to that one tab for the ceremony and removed
  afterwards, so your own passkeys are never touched. The private key, credential
  id, rpId, user handle and sign count are stored in the Keychain as
  `apinj-passkey:<name>`, bound to the origin, written over `security -i` stdin.
  Sign-in uses the same origin gate and consent as the password tools, reads the
  key only after both pass, and saves the new sign count. Results never carry the
  key. The tab must be visible (`tab_not_visible` otherwise). Fixes #2.
- `fill_sms_code` and `fill_email_code`: wait (default 20 s, max 25 s) for the
  newest one-time code that arrived after `since`, from Messages (`chat.db`,
  read-only, including `attributedBody`-only rows) or Gmail (read-only API,
  token file from `APINJ_GMAIL_TOKEN_FILE`), and type it into the one-time-code
  field after the same origin gate and consent as `fill_totp`. Returns only
  `{filled, reason?}`, never the code, message or sender. Missing Full Disk
  Access is `messages_access_denied`; no Gmail token is
  `email_source_unavailable`. A bare number with no code keyword nearby is
  never taken, and a WebOTP line (`@host #code`) for another host is skipped.
  Fixes #3.

## [0.4.0] - 2026-11-09

### Added

- `save_credential {name, origin, username, replace?}` stores a new login in
  the macOS Keychain as `apinj:<name>`, bound to the normalised origin. The
  human types or pastes the password into a native hidden-answer dialog that
  always appears (`APINJ_CONFIRM` does not apply); the value is written via
  `security -i` on stdin, never argv, and never appears in a return value or
  error. `login({domain, name})` finds the entry afterwards. Replacing an entry
  with a different username leaves one item, not two. Passwords the Keychain
  read path would mangle (non-printable or non-ASCII, leading or trailing
  space, over 1024 chars) are refused with `password_unsupported`.

## [0.3.0] - 2026-10-29

### Added

- Saved logins are now read from Vivaldi first (`Vivaldi Safe Storage`), then
  Arc, then the macOS Keychain. The resolved backend is reported as `vivaldi`,
  `arc` or `keychain`.

### Changed

- **Fills are auto-approved by default.** The per-use Allow/Deny dialog no
  longer appears unless you set `APINJ_CONFIRM=1` (or `true`/`yes`/`on`) in the
  server's env; that one switch covers both `login`/`fill_credential` and
  `fill_secret`. Origin binding and the per-keystroke `loaderId` guard still run
  on every fill. `user_denied` is now only returned with the dialog on.
- The Arc reader is now a general Chromium-store reader (`chromiumLookup`) that
  takes a browser name, a `Login Data` path and a Keychain service. A missing
  browser profile is a miss; a denied read is a fault that does not block later
  stores.

## [0.2.2] - 2026-10-14

First release published from CI. 0.2.0 was published by hand and 0.2.1 never
reached npm; this version carries everything in 0.2.1 plus the docs change below.

### Changed

- Releases publish to npm from GitHub Actions over npm trusted publishing
  (OIDC), with a provenance attestation.
- Docs and code comments use neutral examples instead of named sites.

## [0.2.1] - 2026-08-26

Packaging and release-plumbing only. No functional change to the server: 0.2.1
and 0.2.0 behave identically.

### Fixed

- **The published tarball shipped the whole repo.** With no `files` field and no
  `.npmignore`, npm fell back to `.gitignore` and included the entire test suite
  (46 kB of `tools.test.ts` alone), `bun.lock`, the design handoff, and
  `.github/workflows/publish.yml`. A `files` allowlist cuts the tarball from 39
  files / 341 kB unpacked to 19 / 130 kB, keeping all of `src/`, the Keychain
  setup guide the README links to, and the changelog.
- **A failed `npm publish` also swallowed the GitHub Release.** The release step
  was gated behind the publish step succeeding, so when v0.2.0 died with
  `ENEEDAUTH` — the package did not exist on npm yet, so no trusted publisher
  could be registered against it — the release had to be created by hand. The
  two are independent artifacts and now fail independently (`!cancelled()`).

### Note

0.2.0 on npm carries **no provenance attestation**: it was published manually to
bootstrap the package page, and provenance requires the CI OIDC environment. Once
a trusted publisher is registered for this repo + `publish.yml`, later tags
publish from CI with provenance.

## [0.2.0] - 2026-08-26

Adds `fill_secret`: typing a **named, non-credential secret** — an SSN, a
freeze PIN, a date of birth, an account number — into a field, behind the
same origin binding, consent dialog and pre-keystroke `loaderId` guard that a
credential fill gets.

The design problem was not "add a selector argument". A single-purpose script can
take an arbitrary CSS selector safely *because a human typed it*; this server
assumes the caller may be steered by page content, so selector control is denied
by default and granted per entry, at storage time, by the human who stores it.

### Added

- **`fill_secret`** — types a NAMED, non-credential secret (SSN, freeze PIN,
  date of birth, account number) into a field, behind the same origin binding,
  consent dialog and pre-keystroke `loaderId` guard as a credential fill. It
  takes no `domain`: the Keychain entry `apinj:<name>` is the lookup key and its
  stored origin is the binding, and it resolves Keychain-only so an Arc row
  cannot substitute a saved login for the named secret. Returns
  `{ filled, reason? }` — never the value, its length, or a mask of it.
- **Per-entry capability flags** in the Keychain comment attribute, set by a
  human at storage time and defaulting to deny: `sel=allow` permits a
  caller-supplied CSS selector, `kind=text` permits a non-password target field.
  Without them, `fill_secret` must auto-detect (one candidate or refuse) and may
  only type into a `type="password"` input. The bare-origin comment form is
  unchanged. Unknown flags parse and are ignored.
- **Format shaping** (`src/secret.ts`): `raw`, `dashed`, `last4`, `first3`,
  `mid2`, so the same nine digits reach five differently-shaped fields without
  the value passing through the caller. Every format but `raw` asserts exactly
  nine digits and refuses rather than sending.
- **Shadow-DOM piercing** (`PIERCE_FN`, `src/inject.ts`): selectors now resolve
  inputs inside open shadow roots (`<atlas-input>`, Angular Material, Salesforce
  LWC), which a plain `document.querySelector` sees only the host of. It is an
  inline expression rather than a `window.__pierce` global, so a page cannot
  redefine the resolver and choose the target of a later injection.
- **`events` option** on `fill_credential`, `login` and `fill_secret`: an opt-in
  `keydown`/`keypress`/`keyup`/`change` burst after the insert.
  `Input.insertText` fires native `beforeinput`/`input` but no keyboard events,
  so a validator wired to `keyup` reports "criteria not met" against a perfectly
  good value.

### Changed

- The focus verification now walks `shadowRoot.activeElement` before comparing
  identity. `document.activeElement` reports the shadow HOST, so the flat check
  was false for every field piercing reached — piercing and focus-verification
  would otherwise have been mutually exclusive.
- `typeIntoField` now empties the target field (through the native `value`
  setter, plus an `input` event so React observes it) in the same round-trip as
  the focus call. `Input.insertText` inserts at the caret rather than replacing,
  so a pre-filled box previously had the secret concatenated onto its contents
  while the tool reported `filled: true`.
- `parseComment` returns `{ origin, flags }` instead of a bare origin string.
- Synthetic events now set `composed` to match the UA (key events and `input`
  yes, `change` no). `bubbles: true` alone does not cross a shadow boundary, so
  the burst reached no document-level listener on the very pages the piercing
  work exists for.

### Testing

- `test/live-check.ts` (`bun run verify:live`): 26 assertions driving the real
  serialized page-world expressions against a real browser over CDP — two nested
  open shadow roots, a closed one, a pre-filled field, a disabled target. Not
  part of `bun test`, which needs no browser. It is what caught the `composed`
  bug that every shim-based test missed.

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
