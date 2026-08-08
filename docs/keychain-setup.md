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
