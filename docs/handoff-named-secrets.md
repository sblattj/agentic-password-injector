# Handoff — named secrets (non-credential injection)

**Status:** IMPLEMENTED, 2026-08-26. Kept as the design rationale for `fill_secret`; see the
"What shipped" section at the end for where each item landed and what is still unproven.
**Written:** 2026-08-26, from a real campaign that needed this and had to work around its absence.
**Reference implementation ported FROM:** `~/.dotorg/per-res/credit/inject-secret.py` (git-crypt'd repo, ~230 lines, stdlib + `websockets`).

## The gap in one sentence

This server can type **a credential for a domain** (username / password / TOTP, auto-detected);
it cannot type **an arbitrary named secret into an arbitrary field** — an SSN, a freeze PIN, a
date of birth, an account number — which is what a real identity-hardening or form-filling
session spends most of its time doing.

### What forced the workaround

A credit-freeze campaign (2026-08-25 → 26) had to put one SSN into ~7 different bureau forms
without it ever entering an agent transcript, a shell history, or a log. This server could not
do it, so a single-purpose Python script was written alongside it. That script now duplicates —
less safely — machinery this repo already has (CDP plumbing, Keychain reads, focus verification).
The goal of this handoff is to fold the capability in, **without** dissolving the security model
that makes this server different from the script.

## Why you cannot simply port the script

The two tools have **opposite threat models**, and this is the crux of the work:

| | `inject-secret.py` | this server |
|---|---|---|
| Who is trusted | the operator, completely | the operator; **the model is not** |
| Field targeting | caller-supplied CSS selector | auto-detected, refuses on ambiguity |
| Origin binding | none | mandatory (`savedOriginFor`, fails closed on `no_origin_binding`) |
| Consent | none | one dialog per injection, bound origin shown |
| TOCTOU | none | `loaderId` guard re-asserted immediately pre-keystroke (M3) |
| Error surface | Python traceback | fixed reason vocabulary, raw text never escapes |

The script is safe *because a human typed the selector*. This server assumes the caller may be
confused or steered by injected page content. **Accepting a caller-supplied selector for a secret
hands back exactly the power `chooseFields`' ambiguity-refusal exists to withhold** — the model
could be talked into naming a visible attacker-controlled `input` and the SSN renders on screen.

So the deliverable is not "add a selector param." It is: *reproduce the script's reach while
keeping origin binding, consent, and the focus/TOCTOU guarantees.*

## Proposed tool surface

One new tool. Deliberately not folded into `fill_credential`, whose `field` enum is part of its
safety story.

```
fill_secret({ tabId, name, selector?, format? }) -> { filled, reason? }
```

- `name` — required. Selects the Keychain entry `apinj:<name>` (per `resolveCredentialWith`
  rule 1: a supplied name that matches nothing is a MISS, never a substitution).
- `selector` — optional CSS selector. **Only honoured when the stored entry opts in** (below).
  Absent → fall back to `probeFields` + a chooser, same discipline as `chooseOtpField`.
- `format` — optional shaper, see below. Default `raw`.
- Returns `{filled, reason?}` only. **Never** a length, never a masked tail — see "Do not port
  the masking" below.

### Storage convention (extends `docs/keychain-setup.md`)

The origin binding stays mandatory and keeps its current meaning:

```bash
security add-generic-password \
  -s 'apinj:ssn-full' -a "$USER" \
  -w '123456789' \
  -j 'https://www.experian.com'
```

Two new pieces of entry metadata are needed. The comment attribute (`icmt`) is already parsed by
`parseComment` for the origin, so extend that field with a structured form rather than adding a
new lookup path:

```
-j 'https://www.experian.com sel=allow kind=text'
```

- `sel=allow` — the entry permits a caller-supplied `selector`. **Default is deny.** Without it,
  `fill_secret` must auto-detect or refuse. This is the one new security decision, and it is made
  by the *human at storage time*, not by the model at call time.
- `kind=text` — the secret may legitimately land in a non-password input. A password never should;
  an SSN routinely must. Without this, `fill_secret` refuses any field whose `type !== "password"`.
  This replaces the protection `chooseFields` gets for free by keying on `type === "password"`.

Update `parseComment` to return `{origin, flags}` and keep the bare-origin form working — a
comment with no `sel=`/`kind=` must still parse as today, or every existing entry breaks.

## Format shaping

Ported from the script's `shape()`. Real forms demand the same nine digits in five different
shapes, and making the caller do it means the secret passes through the model:

| `format` | Output | Field seen in the wild |
|---|---|---|
| `raw` | stored value verbatim | generated passwords |
| `dashed` | `XXX-XX-XXXX` | Equifax |
| `last4` | last 4 digits | Experian, TransUnion |
| `first3` | first 3 digits | ChexSystems (segmented boxes) |
| `mid2` | middle 2 digits | ChexSystems |

Keep the script's guard: every format except `raw` **asserts exactly 9 digits and exits rather
than sending** if not. A `last4` shaper silently returning the tail of a 4-digit stored value
would send the whole secret.

## Implementation plan, by file

- **`src/vault/keychain.ts`** — extend `parseComment` to `{origin, flags}`; keep bare-origin
  parsing intact. Add `keychainSecret(name)` mirroring the existing lazy-read discipline (I2:
  plaintext read LAZILY, `-g` stderr never reaches a message or log).
- **`src/secret.ts`** *(new)* — `shape(value, format)` with the 9-digit assertion. Pure, trivially
  testable, no I/O.
- **`src/inject.ts`** — two additions, both of which the script proved necessary in the field:
  1. **Shadow-DOM piercing.** `resolveObjectId` uses bare `document.querySelector`, which finds
     only the *host* for a field inside an open shadow root. Port the script's `__pierce`: walk
     open shadow roots breadth-first, and if the hit is a host rather than an input, descend to
     its first inner `input`/`textarea`. Confirmed needed on Experian's `<atlas-input>`, Angular
     Material, and Salesforce Lightning Web Components.
  2. **Post-insert event dispatch, opt-in.** `Input.insertText` fires native `beforeinput`/`input`
     but **no keyboard events**. Vanilla validation widgets that key off `keyup` therefore sit at
     "Criteria not met" while the DOM value is perfectly correct — observed on ID.me's Rails
     password form, 2026-08-26, where all four criteria read invalid against a valid 24-char
     value. Add an optional post-insert `keydown/keypress/keyup/change` burst. Make it opt-in:
     synthesising key events is a capability, not a default.
- **`src/tools.ts`** — register `fill_secret`. Reuse `decideGate`, `confirmInjection`, and the
  `guard` re-assertion verbatim. The consent dialog must name **what** is being typed (the entry
  name) as well as the bound origin, because "type ssn-full into experian.com" is a materially
  different consent than "log in to experian.com".

## Do not port the masking

The script prints `{"ok":…, "field_len":…, "masked":"****…55"}` for read-back verification. **This
server should not.** It already returns `{filled, reason?}` and that is stricter — correctly so.

The masking logic is worth reading anyway as a cautionary tale, because it was wrong twice in one
day. Both bugs shared a root cause: **secrecy is a property of the FORMAT, not the length.** A
naive `len >= 8` test printed the last two digits of a dashed SSN (11 chars), and a segmented box
holding 2–4 digits has "last two" as most of the secret. If you ever add a verification read-back,
key it on format and default to full masking.

## Test plan

Mirror the existing suite; every file below already exists.

- `test/keychain.test.ts` — `parseComment` with bare origin, with flags, with flags in either
  order, with an unknown flag (ignore, don't throw), with `<NULL>`.
- `test/inject.test.ts` — `__pierce` finds an input one and two shadow roots deep; returns the
  inner input when handed a host; returns null on a genuine miss.
- `test/gate.test.ts` — `selector` supplied but entry lacks `sel=allow` → refused. Non-password
  field but entry lacks `kind=text` → refused. Both are the new security boundary; they matter
  more than the happy path.
- `test/leak.test.ts` — `fill_secret` never returns the value, its length, or a masked form, on
  **any** path including every error path.
- `test/totp.test.ts` — unchanged, but confirm `fill_secret` did not regress OTP field choice.

## Field-proven gotchas worth encoding

Each of these cost real debugging time in the campaign that motivated this work:

1. **`Input.insertText` goes to the FOCUSED element, not the selector.** This repo already
   defends it (`FOCUS_CHECK`, I4). The script learned it the hard way: a generated password once
   appended onto a *username* field on a two-step Auth0 login where the password input existed but
   was inert, and the next page rendered it in plaintext. Any `fill_secret` path must keep the
   separate-round-trip focus verification. Do not optimise it into one call.
2. **Two-step login forms.** The password field frequently does not exist on step 1. Refusing
   (`focus_lost`) is correct; silently typing into whatever is focused is the catastrophe.
3. **Deep `activeElement`.** With an open shadow root, `document.activeElement` reports the *host*,
   so an identity check against the inner input always fails. Walk down through
   `shadowRoot.activeElement` before comparing — otherwise piercing and focus-checking are mutually
   exclusive and you will be tempted to drop the check.
4. **A page can validate cosmetically and submit correctly, or vice versa.** Prove which before
   acting: check for framework state (`__reactFiber` and friends) — if there is none, the DOM value
   is what posts and a red indicator is decoration. This distinction decided whether to submit a
   form on both 2026-08-25 (LexisNexis DOB) and 2026-08-26 (ID.me password).
5. **Never let a page read back a field holding a secret via an accessibility snapshot.** On
   2026-08-25 a `take_snapshot` printed every input value on a filled form — SSN included — into
   an agent transcript. The secret was protected on the way IN and leaked on the way OUT. If this
   server ever grows a read-back, it inherits that hazard.

## Definition of done

- An SSN stored once under `apinj:ssn-full` can be typed into all seven bureau forms with no
  caller-side reshaping and no plaintext anywhere outside the Keychain and the page.
- `inject-secret.py` is deleted, not merely superseded.
- Origin binding, consent, and the `guard`/focus guarantees hold on every `fill_secret` path,
  proven by `test/gate.test.ts` and `test/leak.test.ts`.

---

## What shipped

Implemented on `feat/fill-secret`. Every item above landed except where noted.

| Handoff item | Where it landed |
| --- | --- |
| `fill_secret({tabId, name, selector?, format?})` | `fillSecret`, `src/tools.ts` — plus `events?`, below |
| `sel=allow` / `kind=text`, default deny | `parseComment` → `{origin, flags}`, `src/vault/keychain.ts` |
| `parseComment` keeps the bare-origin form | `test/keychain.test.ts`, first two cases unchanged in meaning |
| `keychainSecret(name)`, lazy plaintext read | `src/vault/keychain.ts`; asserted by a `-w`-read counter |
| `shape()` with the nine-digit assertion | `src/secret.ts`, `test/secret.test.ts` |
| Shadow-DOM piercing | `PIERCE_FN`, `src/inject.ts` |
| Opt-in post-insert event burst | `TypeOptions.events`, `src/inject.ts` |
| Reuse `decideGate` / consent / `guard` verbatim | `gatedOnOrigin`, `src/tools.ts` — extracted from `gated`, shared by both |
| Consent names the entry as well as the origin | `buildSecretDialogScript`, `src/consent.ts` |
| No masking, no read-back | return stays `{filled, reason?}`; asserted per branch in `test/leak.test.ts` |
| The five test-plan files | all extended; `test/secret.test.ts` added |

### Decisions taken that the handoff left open

1. **Keychain-only resolution.** The handoff cited `resolveCredentialWith` rule 1, but that
   function tries Arc FIRST and returns an Arc row whose `username === name`. For a secret that
   is a substitution: a saved login's password, from a backend that carries no `sel`/`kind`
   flags. `fillSecret` calls `resolveSecret` (→ `keychainSecret`) directly and never touches the
   credential chain. Proven by `test/gate.test.ts:"VAULT: fill_secret resolves KEYCHAIN-ONLY"`.

2. **No `domain` argument.** The handoff's signature omitted it and that is right: the entry is
   the lookup key and its stored origin is the binding, so a `domain` would only add a second
   caller-chosen string with nothing to bind. This also removes it from the consent dialog.

3. **`PIERCE_FN` is inline, not `window.__pierce`.** The script cached the resolver on the page
   behind `if (window.__pierce) return true`. A script on the matched origin that pre-defines
   that global then chooses the target of every subsequent injection — the exact field control
   `sel=deny` withholds. Deliberately not ported.

4. **Auto-detect is sole-candidate, with no focus tiebreak.** `chooseOtpField`'s discipline was
   the stated model, but its focus fallback is safe only because a name regex ran first and an
   OTP expires in 30s. Neither holds for an SSN, and page focus is one line of attacker script.
   The cost is that real bureau forms will refuse with `ambiguous_secret_field` — which is what
   `sel=allow` is for.

5. **The field is re-inspected on BOTH paths** (`inspectField`). On the selector path it is the
   only place `kind` can be enforced at all; it also refuses an invisible target, which the
   focus check alone does not (an `opacity:0` input takes focus fine).

6. **`typeIntoField` now clears the field**, folded into the existing focus round-trip so the
   guard→insert window does not grow. Not in the handoff, but `Input.insertText` inserts at the
   caret rather than replacing — the same shape as gotcha 1's Auth0 incident, and a live bug for
   `fill_credential` too.

7. **`events` is exposed on `fill_credential` and `login` as well.** The observation that
   motivated it (2026-08-26) was a *password* form.

8. **A sixth gotcha, found while implementing this one.** `bubbles:true` is NOT enough for a
   synthetic event on a field inside a shadow root: without `composed:true` it stops at the
   shadow boundary and reaches no document-level listener at all. The burst therefore did
   nothing on exactly the pages the piercing work exists for — while every unit test stayed
   green, because a shim cannot model event retargeting. `composed` now mirrors the UA,
   verified against real `Input.dispatchKeyEvent` traffic in Chrome 151: key events and `input`
   are composed, `change` is not (and is deliberately left that way — a synthetic event that
   propagates differently from the real one is its own lie).

   That is also why `test/live-check.ts` now exists: 26 assertions driving the real serialized
   expressions against a real browser with two nested open shadow roots and a closed one.
   `bun run verify:live` with a CDP port open. It is not part of `bun test`, which needs no
   browser — but it is the only thing in the repo that could have caught this.

### Definition of done: two of three

- ✅ Origin binding, consent and the `guard`/focus guarantees hold on every `fill_secret` path —
  `test/gate.test.ts` (36 cases) and `test/leak.test.ts` (16 branches × value/length/mask).
- ⚠️ **Not field-verified against a bureau.** 305 unit tests pass, `tsc --noEmit` is clean, the
  server boots over stdio, and `bun run verify:live` puts 26 assertions through a real Chrome
  (piercing two shadow roots deep, refusing a closed one, clearing a pre-filled box, the deep
  focus check, the composed-event burst, `focus_lost` on a disabled target). What is still
  unproven is a real bureau form: no live site has been filled through `fill_secret`, and the
  segmented-box formats in particular are ported logic that has never met a real segmented box.
  Do one real fill before trusting it.
- ⏸️ **`inject-secret.py` is NOT deleted.** Deleting the working tool before the replacement has
  typed a single character into a real form would leave the campaign with neither. Delete it
  after the first successful live `fill_secret`, not before.
