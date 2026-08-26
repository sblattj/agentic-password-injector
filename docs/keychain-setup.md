# Keychain credential setup

Credentials can come from two backends: **Arc**'s saved-login database (read
automatically, no setup) and the **macOS Keychain** (set up by hand, below).

## The origin is required

A Keychain credential must record the origin it belongs to. The injector's
security gate compares the tab's **live** origin against the credential's
**stored** origin, and refuses to type anything if they differ.

A credential with no stored origin is **not injectable** — every tool refuses it
with `no_origin_binding`, without prompting. This is deliberate. The alternative,
falling back to the domain the caller asked for, would mean the gate compared the
tab against a value the caller itself chose, so
`login({ domain: "evil.com", name: "mybank" })` on `evil.com` would pass. The
origin has to come from the vault, not from the request.

## Adding a credential

Store the origin in the generic-password **comment** attribute with `-j`:

```sh
security add-generic-password \
  -s 'apinj:mybank' \
  -a 'alice@example.com' \
  -w 'the-password' \
  -j 'https://auth.mybank.com'
```

- `-s` — service name, always `apinj:<name>`. `<name>` is what you pass as the
  tool's `name` argument.
- `-a` — the username to be typed into the login form.
- `-w` — the password. Omit the value to be prompted instead of putting the
  secret in your shell history.
- `-j` — **the bound origin.** Scheme + host (+ port only if non-default). Use the
  origin of the page that shows the login form, which is not always the origin of
  the main site: many providers log you in on a dedicated host such as
  `https://auth.mybank.com` or `https://login.example.com`.

Check what you stored:

```sh
security find-generic-password -s 'apinj:mybank'   # attributes only, no secret
```

The origin appears as `"icmt"<blob>="https://auth.mybank.com"`. If it shows
`<NULL>`, the entry has no binding and will be refused.

`list_credentials` reports the stored origin (empty when unset), so it is the
quickest way to see which entries still need one.

## Fixing an existing entry

`add-generic-password` will not overwrite. Either update the comment in place:

```sh
security add-generic-password -U -s 'apinj:mybank' -a 'alice@example.com' \
  -w 'the-password' -j 'https://auth.mybank.com'
```

...or delete and re-add:

```sh
security delete-generic-password -s 'apinj:mybank'
```

## TOTP seeds

A time-based one-time-code seed is a separate entry under the `apinj-totp:`
prefix, keyed by the same `<name>`:

```sh
security add-generic-password -s 'apinj-totp:mybank' -a 'alice@example.com' -w 'JBSWY3DPEHPK3PXP'
```

The seed is base32, as printed next to the enrolment QR code. It is read only
inside `fill_totp`, used to compute the current code, and neither the seed nor
the generated code is ever returned to the caller.

## Arc credentials

Arc logins already carry their real origin, so they need no setup and are
unaffected by the rule above.

## Named secrets (non-credential values)

An SSN, a credit-freeze PIN, a date of birth, an account number: a value that is
not a login and has no username. It lives in the **same** `apinj:<name>`
namespace as a credential and is read by `fill_secret`.

```sh
security add-generic-password \
  -s 'apinj:ssn-full' \
  -a "$USER" \
  -j 'https://www.experian.com sel=allow kind=text' \
  -w
```

- `-w` with **no value must come LAST** — it then prompts for the secret instead
  of putting it in your shell history. `-w` followed by another flag swallows
  that flag as the password. Prompt for anything that matters.
- `-a` is required by `security` itself, but the injector ignores it for a
  secret: there is no username to type and none is ever shown. `"$USER"` is a
  fine placeholder.
- `-j` is the bound origin **plus optional flags**, space-separated in any order.

### The two flags

Both default to **deny**. They are the only things that widen what
`fill_secret` may do with a value, and they are set by *you*, with `security`, at
storage time — never by the calling model at call time. That is the whole
difference between this and a script that takes a CSS selector on the command
line: the script trusts the operator, this server assumes the caller may have
been steered by something it read on a page.

| Flag | Without it | With it |
| --- | --- | --- |
| `sel=allow` | a caller-supplied `selector` is refused (`selector_not_allowed`); the field must be auto-detected | the caller may name the field, including inside open shadow roots |
| `kind=text` | the secret may only land in a `type="password"` input (`kind_not_allowed` otherwise) | it may land in an ordinary text box, which is where an SSN actually lives |

Grants are exact strings: `sel=ALLOW` and `kind=TEXT` are **not** grants.
Unknown flags parse and are ignored, so a typo does not brick the entry — but it
does not grant anything either. A comment with flags and no origin has no
binding at all and is refused with `no_origin_binding`.

Without `sel=allow`, auto-detection is deliberately strict: **one candidate field
or refuse.** There is no naming heuristic and no focus tiebreak, unlike the OTP
path — an SSN announces nothing about itself, does not expire in thirty seconds,
and page script can focus whatever it likes. A real bureau form has a dozen text
boxes and will therefore refuse with `ambiguous_secret_field`. That is what
`sel=allow` is for.

### Formats

Real forms want the same nine digits five different ways. Shaping happens inside
the server, after the vault read, so the caller never handles the value:

| `format` | Sends | Seen at |
| --- | --- | --- |
| `raw` (default) | the stored value verbatim | generated passwords |
| `dashed` | `123-45-6789` | Equifax |
| `last4` | `6789` | Experian, TransUnion |
| `first3` | `123` | ChexSystems (segmented boxes) |
| `mid2` | `45` | ChexSystems (segmented boxes) |

Every format except `raw` **asserts exactly nine digits and refuses rather than
sending** (`format_mismatch`). Without that assertion, `last4` on a four-digit
stored value returns the whole value.

### Checking what you stored

```sh
security find-generic-password -s 'apinj:ssn-full'   # attributes only, no secret
```

The comment appears as
`"icmt"<blob>="https://www.experian.com sel=allow kind=text"`. If it shows
`<NULL>`, the entry has no binding and will be refused.

### One secret, several sites

The origin binding is per entry, so a value needed on seven different sites
needs seven entries — one per bound origin — holding the same secret:

```sh
for host in www.experian.com www.equifax.com www.transunion.com; do
  security add-generic-password -s "apinj:ssn-${host%%.*}" -a "$USER" \
    -j "https://$host sel=allow kind=text" -w
done
```

That is deliberate. A single entry bound to nothing, or bound to a wildcard,
would mean the gate compares the tab against a value that matches everything —
which is no binding at all.
