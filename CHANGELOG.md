# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
