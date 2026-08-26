# agentic-password-injector

**A self-hosted version of 1Password's Secure Agentic Autofill / Infisical's Agent Vault — built on the password store your browser already has, the macOS Keychain, and a CDP connection. No subscription, no credential migration, and the model never sees the secret.**

It is an [MCP](https://modelcontextprotocol.io) server with four tools. When your agent hits a login wall, it calls `login({tabId, domain})`; the credential is read from a local vault and typed straight into the page's DOM inside *this* process. The only thing that crosses back into the model's context is `{filled: true}`.

---

## Why

Any secret that enters an LLM's context window must be treated as compromised. Transcripts are logged and cached, tool results are replayed on every subsequent turn, and a prompt injection on the page you're automating can ask the model to repeat what it just read. So the naive fix — decrypt a saved password, then type it with a normal `type_text` tool call — leaks it twice over (once in the tool call's arguments, once in the transcript) and ends with a password rotation.

The industry answer is **credential injection by a non-model component**: a separate process holds the secret and puts it into the page on the agent's behalf. That is exactly what this is, except the "vault" is the one already on your machine.

---

## Security model

This is the part that matters, so every claim below points at the code that implements it. If you're evaluating this, read those symbols rather than trusting this list.

### 1. No tool ever returns a secret

The secret is fetched from the vault and dispatched at the page as real keystrokes (`Input.insertText`) entirely inside the MCP process. Every tool's return type is `FillResult = { filled: boolean; submitted?: boolean; reason?: string }` (`src/tools.ts`) — there is no field a password could travel in, and no reveal tool exists. Failure `reason`s come from a **fixed vocabulary** (`origin_mismatch`, `user_denied`, `vault_locked`, …); raw error text never escapes a tool, because a decrypt/Keychain error message can carry unaudited state (`secretFailReason` / `vaultFailReason` in `src/tools.ts`).

`test/leak.test.ts` is the load-bearing test: it drives `login`, `fill_totp` and `fill_secret` through *every* return branch with a sentinel secret and asserts the sentinel — and, for `fill_secret`, its length and any mask of it — appears in no return value and no thrown message — and then asserts the sentinel *did* reach `typeIntoField`, so the absence-assertions are provably non-vacuous rather than testing nothing.

The plaintext's lifetime is also bounded on purpose: it is zeroed in a `finally` the moment the keystrokes are out (`login` / `fillCredential` in `src/tools.ts`), and the CDP dispatcher clears each command's timeout on settle, so a stale timer closure cannot keep the `Input.insertText` params — i.e. the password — reachable for the timeout window (`createDispatcher`, `src/cdp.ts`).

### 2. Mandatory origin match, checked *before* the consent dialog

Every credential is bound to an origin **that comes from the vault, never from the request** (`savedOriginFor`, `src/tools.ts`). Before anything is typed, the tool reads the tab's **live** origin over CDP (`getOrigin`, `src/cdp.ts` — evaluated in the tab, never taken from the cached target-list URL) and compares it with `originMatches` (`src/origin.ts`, a normalized scheme+host+port equality, not a substring test).

That comparison happens **before** `confirmInjection` is called, so a mismatched tab cannot even raise a dialog — an attacker-controlled page must not be able to make you answer a prompt about someone else's domain. `decideGate` (`src/gate.ts`) is then the second, authoritative check, and it evaluates origin-match *first*, so a mismatch is refused regardless of what the user answered.

### 3. The origin is re-asserted immediately before every keystroke (the TOCTOU close)

The consent dialog blocks for up to 60 seconds. In that window the tab can be navigated away — by a page timer, a meta-refresh, a subframe navigating the top, or, most directly, the same prompt-injected model calling `navigate_page` through its own browser MCP. You truthfully approved `mybank.com`; the password lands on `evil.com`.

So a `Guard` (`src/tools.ts`) re-reads **both** the live origin **and** the main frame's `loaderId` (`getLoaderId`, `src/cdp.ts` — a browser-side identity for the current document load, read from the `Page` domain rather than from page-world JS) and runs immediately before *every* keystroke, not once before the pair. A same-origin string can survive a navigation, but any top-level document commit mints a new `loaderId`; both must be unchanged or the fill aborts with `navigated_during_consent`, having typed nothing.

The final re-assertion is *inside* `typeIntoField` (`src/inject.ts`), as the last thing before `Input.insertText` — `resolve → focus → verify → guard → insert` — because a commit landing in the guard→`resolveObjectId` sub-window would otherwise leave a valid objectId on the *new* document (the selector stamp is deterministic and pre-placeable by an attacker page). If `submit: true` is requested, the guard runs again before the click, too.

Both facts are also required to be *knowable*: an empty `loaderId` fails closed as `tab_unavailable`, never as "unchanged".

### 4. A per-use native Allow/Deny dialog

Each fill raises a real macOS dialog (`buildDialogScript` / `confirmInjection`, `src/consent.ts`) showing the **bound host and the username** — never the password. It defaults to **Deny**, and anything other than an explicit Allow (including the 60-second timeout and any osascript failure) is a denial. The caller-supplied domain is unauthenticated text, so it is rendered only as trailing context and only when it is domain-shaped and under 64 chars (`safeRequestedDomain`) — otherwise the dialog shows the vault-derived origin alone, so a caller can't pad the prompt or talk you into clicking Allow.

### 5. Keychain credentials fail closed with no stored origin

A credential with no bound origin cannot be gated, so it is not injectable: `no_origin_binding`, refused before the connection and before any prompt (`gated`, `src/tools.ts`). There is deliberately **no** fallback to the caller's domain — that would mean comparing the tab against a value the caller chose, i.e. no binding at all, and `login({domain: "evil.com", name: "mybank"})` on `evil.com` would pass. Arc logins carry their real origin already; Keychain entries carry whatever you stored in `-j` (see below).

### 6. No reveal path, and no enumeration oracle

`list_credentials` is metadata-only — origin, username, backend, `has_totp`. It never calls `getSecret()`, and the Keychain backend reads the password **lazily**: lookup reads attributes only, and `-w` (the secret) runs inside `getSecret()`, i.e. only on a path that already passed the origin gate *and* the dialog (`keychainLookup`, `src/vault/keychain.ts`).

Because `list_credentials` has no dialog and no origin gate (correctly — it returns no secrets), it is the cheapest sweep surface in the server, so lookups are refused for any key that would match everything: a bare TLD (`com`) or a public suffix (`co.uk`) is rejected by `isValidDomain` at the entry point (`src/tools.ts`) *and* independently by `isRegistrableDomain`/`hostMatches` in the vault (`src/vault/arc.ts`), which matches on label boundaries so `evilmybank.com` never satisfies `mybank.com`. Neither check is allowed to be the only one.

### 7. Faults never masquerade as misses

A locked Keychain, a denied ACL, or an unreadable Arc `Login Data` is a **vault error**, not `not_found` — reporting the latter reads as "you have no such credential" and sends you (or a retrying agent) hunting for an entry that was never the problem. `isItemNotFound` (`src/vault/keychain.ts`) treats only `errSecItemNotFound` as a miss; `classifyCopyError` (`src/vault/arc.ts`) distinguishes ENOENT from denial; and an Arc fault does not hide a Keychain credential but *is* re-thrown if every backend misses (`resolveCredentialWith`, `src/vault/index.ts`).

### 8. It refuses to guess which field to type into

Field choice is a pure, unit-tested function over what the page reports, not a `querySelector` gamble:

- **Honest visibility.** `offsetParent` is not a visibility test — it is truthy for an `opacity: 0`, `0×0`, or clipped input. A hidden decoy password box earlier in DOM order is a credential-capture primitive for anyone with script on the matched origin, so visibility means a non-zero rendered box, not `display:none`/`visibility:hidden`, and non-transparent (`VISIBLE_FN`, `src/inject.ts`).
- **Ambiguity refuses.** Two visible password inputs → `ambiguous_password_field`, not a coin flip reported as `filled: true` (`chooseFields`, `src/inject.ts`). An unlabelled username box is accepted only when it is the sole candidate (`chooseUsernameField`, `src/tools.ts`).
- **Focus is verified**, in its own round-trip immediately before inserting: `Input.insertText` lands wherever focus *is*, and `.focus()` can be silently undone by an `onfocus` handler or an async focus-steal. Failure throws `focus_lost` and nothing is typed (`FOCUS_CHECK`, `src/inject.ts`). The check is boolean-only — it never reads `value`, so it is not a reveal path.
- **OTP fields are matched conservatively.** A bare "code" is deliberately *not* matched: "Zip code" and "Promo code" routinely precede the real OTP box, and typing a live one-time code into one is a disclosure (`OTP_RE`, `src/tools.ts`). Probe stamps are unique per call, so a stale attribute from a previous probe cannot make a later selector resolve to the wrong element.
- **Shadow roots are pierced, but nothing is installed on the page.** A field inside an open shadow root (`<atlas-input>`, Angular Material, Salesforce LWC) is invisible to `document.querySelector`, which finds only the host — so focus lands on the host and the keystroke goes elsewhere. `PIERCE_FN` (`src/inject.ts`) walks open shadow roots breadth-first as an **inline expression**, never a cached `window.__pierce` global: a page that pre-defines such a global would choose the target of every later injection. The focus check walks `shadowRoot.activeElement` down to the same element before comparing, so piercing and focus-verification are not mutually exclusive.

### 9. Named secrets are a narrower capability, not a selector API

`fill_secret` reaches fields the credential tools deliberately will not — an SSN box, a freeze PIN, a segmented date of birth. The obvious way to build it is to accept a CSS selector, which is what a single-purpose script does safely *because a human typed the selector*. This server assumes the caller may be steered by page content, so handing it selector control would give back exactly the power the ambiguity refusal in §8 exists to withhold: name a visible attacker-controlled `input`, and the SSN renders on screen.

So the reach is granted **per entry, at storage time, by a human**, in the Keychain comment attribute (`parseComment`, `src/vault/keychain.ts`):

- `sel=allow` — this entry permits a caller-supplied `selector`. **Default deny.**
- `kind=text` — this secret may land in a non-password input. **Default deny**, which is the protection `chooseFields` gets for free by keying on `type === "password"`.

Everything else is unchanged: the origin binding is mandatory and fails closed, one consent dialog per injection (naming the *entry* as well as the bound origin, because "type ssn-full into forms.example.com" is a different question from "log in to forms.example.com"), and the `loaderId` guard re-asserted immediately before the keystroke. Resolution is **Keychain-only** — routing through the credential chain would let an Arc row whose username matched the name substitute a saved login, from a backend that carries no flags.

Without `sel=allow`, auto-detection is one candidate or refuse (`chooseSecretField`, `src/tools.ts`). There is no naming heuristic and no focus tiebreak, unlike the OTP path: an SSN announces nothing about itself, does not expire in thirty seconds, and page script can focus whatever it likes. Adding an input creates ambiguity, and ambiguity refuses — so script on the matched origin can *deny* a fill but cannot redirect one.

Formats (`dashed`, `last4`, `first3`, `mid2`) are shaped inside the server so the caller never handles the value, and each **asserts exactly nine digits and refuses rather than sending** (`shape`, `src/secret.ts`) — without that, `last4` on a four-digit stored value returns the whole value. Nothing is read back: the return stays `{filled, reason?}`, with no length and no mask. The reference implementation's masking was wrong twice in one day for the same reason — secrecy is a property of the **format**, not the length, and a naive `len >= 8` test printed the last two digits of an 11-character dashed SSN.

---

## Non-goals and honest limitations

- **Not a password manager.** It reads existing vaults. No create, edit, generate, or delete.
- **It does not make banking hands-free.** Every fill is gated behind a human clicking Allow, per use. This makes agent-assisted login *possible with you approving each step*, not autonomous. If that's what you wanted, this is the wrong tool.
- **No SMS or email OTP.** Those can't be vaulted. Authenticator-app TOTP works only if you store the seed yourself.
- **macOS only.** The vault backends shell out to `security`, the Arc store lives under `~/Library`, and the consent dialog is `osascript`.
- **Chromium-family browser with a CDP debug port required.** Arc, Chrome, Edge, Brave. No Firefox, no Safari.
- **Arc is the only browser *vault* backend.** Chrome's own store is not read yet (the backend interface is pluggable; a `1password-op` backend doesn't exist either).
- **Bun-only.** `bun:sqlite`, `bun:test`, and direct `.ts` imports have no node equivalent, so there is no node engine range that would be true. Not zero-dependency either: it depends on `@modelcontextprotocol/sdk`.
- **The origin gate is the security boundary, and it is only as good as the stored origin.** A credential bound to a page that itself has an XSS is still injectable into that page.

---

## The five tools

| Tool | Arguments | Returns |
| --- | --- | --- |
| `list_credentials` | `domain` (required), `name?` | `{ credentials: [{ origin, username, backend, has_totp }], reason? }` |
| `fill_credential` | `tabId`, `domain`, `field: "username" \| "password"` (required), `name?`, `events?` | `{ filled, reason? }` |
| `login` | `tabId`, `domain` (required), `name?`, `submit?: boolean`, `events?` | `{ filled, submitted, reason? }` |
| `fill_totp` | `tabId`, `domain` (required), `name?`, `selector?` | `{ filled, reason? }` |
| `fill_secret` | `tabId`, `name` (required), `selector?`, `format?`, `events?` | `{ filled, reason? }` |

- `tabId` is a **CDP target id** — always explicit, never "the active tab".
- `domain` is the domain of the *saved credential* (`github.com`), and must be a registrable domain.
- `name` selects a specific credential when several share a domain: an Arc row whose username is `name`, or the Keychain entry stored under `apinj:<name>`. A supplied `name` that matches nothing is a miss, never a substitution — returning a different account would show the wrong username in the dialog.
- `login` is one origin check and **one** dialog for username + password (+ optional submit). `fill_credential` exists for identifier-first flows (Google, Microsoft) where the password field isn't on the page yet.
- `fill_totp` reads the seed, computes the code, types it, and drops both. Neither is ever returned.
- `fill_secret` types a **named non-credential secret** — an SSN, a freeze PIN, a date of birth, an account number. It takes no `domain`: the Keychain entry `apinj:<name>` *is* the lookup key, and its stored origin is the binding. See [named secrets](#9-named-secrets-are-a-narrower-capability-not-a-selector-api) below and `docs/keychain-setup.md`.
- `events` fires a synthetic `keydown`/`keypress`/`keyup`/`change` burst after the insert. `Input.insertText` fires native `beforeinput`/`input` but **no keyboard events**, so a validator wired to `keyup` shows "criteria not met" against a value that is actually correct. Opt-in, because synthesising key events makes the page believe a human typed.

Common `reason` codes: `origin_mismatch`, `user_denied`, `navigated_during_consent`, `no_origin_binding`, `not_found`, `vault_locked`, `vault_error`, `focus_lost`, `ambiguous_password_field`, `no_password_field`, `no_username_field`, `no_otp_field`, `no_totp`, `bad_domain`, `tab_unavailable`.

`fill_secret` adds: `name_required`, `bad_name`, `bad_format`, `format_mismatch`, `selector_not_allowed`, `kind_not_allowed`, `field_not_visible`, `no_secret_field`, `ambiguous_secret_field`.

---

## Quickstart

**1. Install** ([Bun](https://bun.sh) required):

```sh
git clone https://github.com/sblattj/agentic-password-injector.git
cd agentic-password-injector
bun install
bun test          # 206 tests
```

**2. Start a Chromium-family browser with a debug port:**

```sh
# Chrome
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --remote-debugging-port=9222
# Arc
"/Applications/Arc.app/Contents/MacOS/Arc" --remote-debugging-port=9222
```

The default is `http://127.0.0.1:9222`. A browser on a different port is pointed at with the `CDP_BASE` env var (e.g. `CDP_BASE=http://127.0.0.1:9333`); `CDP_TIMEOUT_MS` (default 15000) bounds each CDP command.

**3. Register the MCP server.** With Claude Code:

```sh
claude mcp add agentic-password-injector -- \
  "$HOME/.bun/bin/bun" "$PWD/src/mcp.ts"
```

Or, for a stdio-MCP inventory in TOML form:

```toml
[servers."agentic-password-injector"]
command = "~/.bun/bin/bun"
args = ["/path/to/agentic-password-injector/src/mcp.ts"]

[servers."agentic-password-injector".env]
CDP_BASE = "http://127.0.0.1:9222"
```

No secrets belong in that file — the server reads them from the vault at use time.

The first fill will make macOS prompt for Keychain access (for the Arc `Safe Storage` key) and may need Full Disk Access for the Arc store; grant it to the process running Bun.

---

## Importing credentials

**Arc — nothing to do.** Arc's saved logins are read directly and already carry their real origin.

**macOS Keychain — one command per credential.** The origin goes in the generic-password *comment* attribute (`-j`), and is **mandatory**: without it the credential is refused with `no_origin_binding`.

```sh
security add-generic-password \
  -s 'apinj:mybank' \
  -a 'alice@example.com' \
  -w 'the-password' \
  -j 'https://auth.mybank.com'
```

`-s` is always `apinj:<name>`, and `<name>` is what you pass as the tool's `name`. Use the origin of the page that *shows the login form* — often a dedicated host like `https://auth.mybank.com`, not the main site. Omit `-w`'s value to be prompted instead of putting the secret in your shell history.

A TOTP seed is a separate entry under `apinj-totp:<name>`:

```sh
security add-generic-password -s 'apinj-totp:mybank' -a 'alice@example.com' -w 'JBSWY3DPEHPK3PXP'
```

Full details, verification commands, and how to fix an entry that's missing its origin: [`docs/keychain-setup.md`](docs/keychain-setup.md).

---

## How it compares

|  | agentic-password-injector | 1Password Secure Agentic Autofill | Infisical Agent Vault |
| --- | --- | --- | --- |
| Model never sees the secret | ✅ | ✅ | ✅ |
| Self-hosted / local-only | ✅ entirely on your machine | ❌ hosted service | ✅ self-hostable |
| Subscription | none | paid plan | open-core |
| Credential migration | none — reads Arc + Keychain in place | import into 1Password | store secrets in the vault |
| Per-use human approval | ✅ native dialog, defaults to Deny | ✅ | policy-based |
| Origin binding enforced from the vault | ✅ + re-asserted per keystroke | ✅ | n/a (not browser-autofill shaped) |
| Platforms | macOS only | macOS, Windows, Linux | cross-platform |
| Browsers | Chromium-family over CDP | first-party extension + browser support | n/a |
| Polish, support, audits | one-person project, no audit | commercial, audited | commercial, audited |
| Scope | browser login autofill | browser login autofill | app/service secrets broadly |

Be clear-eyed about it: the commercial products are more polished, cross-platform, supported, and independently audited. This one's advantages are that it's yours, it's free, it reads the vaults you already have, and you can read all of it in an afternoon.

---

## HARD RULES for the calling agent

> **1. Never take a DOM snapshot, accessibility snapshot, screenshot, or `innerText` dump of a page you just filled, between the fill and the submit.**

The whole design keeps the secret out of your context — and then a single `take_snapshot` of the page you just filled can put it right back in, because a password input's value (or a site's "show password" state) can surface in a snapshot or a screenshot. Fill, submit, *then* look. If you need to verify, verify the post-submit page.

This is not hypothetical, and it is worse for `fill_secret` than for a password: on 2026-08-25 an accessibility snapshot of a filled identity form printed **every input value, SSN included**, into an agent transcript. The secret was protected on the way in and leaked on the way out. A `type="text"` SSN box — which is exactly what `kind=text` exists to allow — has none of the masking a password input gets.

Related: `login({submit: true})` exists precisely so the fill-and-submit sequence needs no intermediate look.

> **2. A red validation indicator is not evidence the value is wrong.**

A page can validate cosmetically and submit correctly, or the reverse. Before acting on what the form *looks* like, establish which: if the field has no framework state attached (`__reactFiber` and friends), the DOM value is what posts and the indicator is decoration. If a validator is keyed to `keyup`, `Input.insertText` never fires one — pass `events: true` rather than concluding the fill failed and typing it again.

> **3. A refusal is the tool working.**

`ambiguous_secret_field`, `kind_not_allowed`, `selector_not_allowed` and `focus_lost` all mean *nothing was typed*. None of them is fixed by retrying with different arguments — `selector_not_allowed` and `kind_not_allowed` are fixed only by the human changing the stored entry, and `ambiguous_secret_field` means the page has more than one candidate field and the server will not guess between them. Report the refusal; do not work around it.

## Coordinating with cdp-toolkit

This works well alongside a general browser-driving MCP such as [cdp-toolkit](https://github.com/sblattj/cdp-toolkit) — the agent navigates and clicks with that, and calls this only for the password box. Two things to know:

- **Both drive the same browser, over separate CDP connections.** This server does not share the other's socket or reuse its target resolution; point both at the same `CDP_BASE`.
- **This server always takes an explicit `tabId` and never acts on "the active tab."** That's deliberate: with two MCPs steering one browser, "active" is a race, and a race that picks the wrong tab is a password in the wrong page. Get the target id from your browser MCP's page listing and pass it in.

---

## Development

```sh
bun test              # unit + leak tests, no browser needed
bun run typecheck     # tsc --noEmit
bun run smoke         # entrypoint starts; pass TOML=<servers.toml> to also check registration
bun run mcp           # run the server on stdio

# Drives the real serialized page-world expressions against a REAL browser:
# piercing two shadow roots deep, the deep focus check, field clearing, and the
# composed-event burst. No secret involved; it opens its own tab and closes it.
CDP_BASE=http://127.0.0.1:9222 bun run verify:live
```

`test/live-check.ts` earns its place: the unit suites drive those expressions against a shim,
and a shim cannot model shadow-DOM event retargeting. The post-insert burst shipped once with
`bubbles:true` alone — which reaches no listener outside the shadow root, i.e. it did nothing on
exactly the pages piercing exists for — with every unit test green. Only the live check caught it.

## License

MIT © 2026 Stephen Blatt
