# cookie-dump

A Linux tool that extracts cookies from locally installed browsers, decrypts
them where needed, and writes them to `<browser>_cookies.json` — a practical
companion to the article's filesystem-level cookie extraction experiment
([article.md](../article.md)).

Supported browsers: **Chrome**, **Chromium**, **Brave**, **Firefox**, and
**Firefox Developer Edition**.

> ⚠️ **Security warning** — the JSON files produced by this tool contain live
> session credentials. Anyone holding one can authenticate to your accounts
> without your password. Keep the files private and delete them when done.

## Build

Requires [Go](https://go.dev/) (no cgo — the result is a single static
executable):

```bash
make build          # -> dist/cookie-dump
make clean          # remove dist/
```

Or manually:

```bash
go build -trimpath -ldflags="-s -w" -o dist/cookie-dump .
```

## Usage

```bash
./dist/cookie-dump -browser all      # every installed browser
./dist/cookie-dump -browser chromium # a single browser
./dist/cookie-dump -browser firefox-dev # Firefox Dev Edition only
```

| Flag | Values | Default |
|---|---|---|
| `-browser` | `chrome` `chromium` `brave` `firefox` `firefox-dev` `all` | `all` |

The output directory is fixed: every file is written to `./out`
(`out/chrome_cookies.json`, `out/chromium_cookies.json`, …). The directory is
created automatically if it does not exist.

Each installed browser produces one file: `chrome_cookies.json`,
`chromium_cookies.json`, `brave_cookies.json`, `firefox_cookies.json`,
`firefox-dev_cookies.json`. Browsers that are not installed are skipped.

## Output format

```json
{
  "domain": ".example.com",
  "name": "session",
  "value": "plaintext-or-redacted",
  "encrypted": false,
  "path": "/",
  "secure": true,
  "httpOnly": true,
  "sameSite": "lax",
  "isPersistent": true,
  "priority": "medium",
  "creationTime": "2025-09-17T13:41:23Z",
  "lastAccessTime": "2026-10-19T00:21:27Z",
  "expires": "2026-10-22T13:41:23Z",
  "baseDomain": "example.com",
  "originAttributes": ""
}
```

| Field | Source | Notes |
|---|---|---|
| `domain` | `host_key` (Chromium) / `host` (Firefox) | includes leading dot for host-only matching |
| `name`, `value` | `name` / `value` | see decryption below |
| `encrypted` | — | `true` when the stored value could **not** be decrypted; `value` is then redacted |
| `secure`, `httpOnly` | `is_secure`, `is_httponly` / `isSecure`, `isHttpOnly` | |
| `sameSite` | `samesite` / `sameSite` | normalized to `unspecified` / `no_restriction` / `lax` / `strict` / `none` |
| `isPersistent`, `priority` | Chromium only | |
| `creationTime`, `lastAccessTime`, `expires` | timestamps | normalized to RFC 3339 (UTC) |
| `baseDomain`, `originAttributes` | Firefox only | omitted when the schema lacks them |

Timestamps come from two different epochs — Chromium stores microseconds
since 1601, Firefox stores PRTime microseconds since 1970 (except `expiry`,
which is seconds) — both are converted for you.

## How decryption works

The browser keeps its cookie database open, so the tool first copies the
database to a temp file before reading it (article step 4.2).

**Chromium family (Chrome / Chromium / Brave)** — values live in the
`encrypted_value` BLOB column:

```text
blob  = "v10"|"v11" + AES-128-CBC(spaces IV) ciphertext
key   = PBKDF2-HMAC-SHA1(password, "saltysalt", 1 iteration, 16 bytes)
        password: "peanuts" for v10, keyring secret for v11
plain = PKCS#7-unpadded decryption
```

In Chrome's newer cookie-store schema (v24), the decrypted plaintext is
`SHA256(host_key) ++ cookie_value` — a domain-binding integrity hash. The
tool verifies that hash and strips it, exactly like Chromium. Decryption
that fails Chromium's own "empty key" fallback (PBKDF2 of `""`) is kept in
the JSON with `encrypted: true` and a redacted value — the tool never
crashes on secrets it cannot recover.

If the "Safe Storage" secret is missing from the keyring (or the KWallet /
KeePassXC variant is missing), `v11` cookies stay redacted.

**Firefox / Firefox Developer Edition** — no decryption needed: Firefox
stores cookie values in plaintext in the `value` column (verified against
`netwerk/cookie/CookiePersistentStorage.cpp`; the `key4.db`/NSS machinery
only protects saved *passwords*, not cookies).

## Requirements

- Linux
- A running session D-Bus with a Secret Service implementation, required
  only for Chromium-family browsers using `v11` encryption
- Go 1.21+ to build

## Repository hygiene

The `.gitignore` in this folder excludes the built binary, `dist/`, and —
most importantly — every `*_cookies.json` and `out/` directory, so
extracted session credentials can never be committed by accident.
