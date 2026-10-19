package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1" //nolint:gosec // Chromium's v10/v11 scheme mandates PBKDF2-HMAC-SHA1
	"crypto/sha256"
	"database/sql"
	"fmt"
	"io"
	"os"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/pbkdf2"
	_ "modernc.org/sqlite"
)

// Chromium timestamp: microseconds since 1601-01-01.
const chromiumEpochDelta = int64(11644473600000000) // 1601 -> 1970, in microseconds

var chromiumCookieQuery = `
SELECT host_key, name, value, encrypted_value, path,
       is_secure, is_httponly, samesite, is_persistent, priority,
       creation_utc, last_access_utc, expires_utc
FROM cookies`

// readChromium locates the cookie DB, copies it to a temp file (the browser
// keeps the original open, just like the article's step 4.2) and extracts
// every cookie, decrypting encrypted_value blobs where possible.
func readChromium(b Browser) ([]Cookie, error) {
	var dbPath string
	for _, p := range b.ChromiumPaths {
		if _, err := os.Stat(p); err == nil {
			dbPath = p
			break
		}
	}
	if dbPath == "" {
		return nil, os.ErrNotExist
	}

	copyPath, cleanup, err := copyToTemp(dbPath)
	if err != nil {
		return nil, fmt.Errorf("copying database: %w", err)
	}
	defer cleanup()

	db, err := sql.Open("sqlite", copyPath)
	if err != nil {
		return nil, fmt.Errorf("opening copy: %w", err)
	}
	defer db.Close()

	rows, err := db.Query(chromiumCookieQuery)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	// v11 blobs carry a keyring-derived key ("* Safe Storage").
	// Only one key is usually present; lazily resolve the first one that works.
	var keyringKey []byte
	var keyringTried bool

	var out []Cookie
	for rows.Next() {
		var (
			hostKey, name, value, path string
			encValue                   []byte
			isSecure, isHttpOnly       int
			sameSite, isPersistent     int
			priority                   int
			creation, lastAccess, exp  int64
		)
		if err := rows.Scan(&hostKey, &name, &value, &encValue, &path,
			&isSecure, &isHttpOnly, &sameSite, &isPersistent, &priority,
			&creation, &lastAccess, &exp); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}

		c := Cookie{
			Domain:         hostKey,
			Name:           name,
			Path:           path,
			Secure:         isSecure == 1,
			HttpOnly:       isHttpOnly == 1,
			SameSite:       chromiumSameSite(sameSite),
			IsPersistent:   isPersistent == 1,
			Priority:       chromiumPriority(priority),
			CreationTime:   formatChromiumTime(creation),
			LastAccessTime: formatChromiumTime(lastAccess),
			Expires:        formatChromiumTime(exp),
		}

		decrypted, redacted := decryptChromiumValue(string(encValue), value, hostKey, &keyringKey, &keyringTried, b.KeyringApps)
		c.Encrypted = redacted
		c.Value = decrypted
		out = append(out, c)
	}
	return out, rows.Err()
}

// decryptChromiumValue returns the plaintext value. If no value column data
// exists and the encrypted blob cannot be decrypted, the value is redacted.
//
// Crypto scheme (verified against shipped Chromium, branches M133..M154):
//
//	blob  = "v10"|"v11" + AES-128-CBC(spaces IV) ciphertext
//	key   = PBKDF2-HMAC-SHA1(password, "saltysalt", 1 iteration, 16 bytes)
//	        password = "peanuts" for v10, keyring secret for v11
//	        (with the empty-password key as Chromium's own fallback)
//	plain = PKCS#7-unpadded decryption
//
// From cookie-store schema version 24, the plaintext is
// SHA256(host_key) ++ cookie_value: a domain-binding integrity hash.
// We verify the hash and strip it; for older rows it is absent, so a
// mismatch simply means we return the value as-is.
func decryptChromiumValue(encValue string, plainValue, hostKey string, keyringKey *[]byte, keyringTried *bool, apps []string) (string, bool) {
	if encValue == "" {
		return plainValue, false // legacy plaintext row
	}
	if len(encValue) < 3 {
		return "", true
	}
	prefix, payload := encValue[:3], []byte(encValue[3:])

	var key []byte
	switch prefix {
	case "v10":
		key = deriveChromiumKey([]byte("peanuts"))
	case "v11":
		if !*keyringTried {
			*keyringTried = true
			*keyringKey = safeStorageKey(apps) // may return nil on failure
		}
		if len(*keyringKey) == 0 {
			return "", true // keyring unavailable -> stay redacted
		}
		key = deriveChromiumKey(*keyringKey)
	case "v20":
		// App-bound encryption (Windows-only scheme); unsupported on Linux.
		return "", true
	default:
		return "", true
	}

	plain, ok := decryptCBCStrictPKCS7(key, payload)
	if !ok {
		// Chromium itself retries with the empty-password key.
		plain, ok = decryptCBCStrictPKCS7([]byte(emptyKeyHex), payload)
	}
	if !ok {
		return "", true
	}

	// Cookie-store schema v24+: leading 32 bytes are SHA256(host_key).
	if len(plain) >= sha256.Size {
		want := sha256.Sum256([]byte(hostKey))
		if sameBytes(plain[:sha256.Size], want[:]) {
			plain = plain[sha256.Size:]
		}
	}

	if !utf8.ValidString(string(plain)) {
		return "", true
	}
	return string(plain), false
}

// emptyKeyHex is PBKDF2-HMAC-SHA1("", "saltysalt", 1 iteration), Chromium's
// documented empty-password fallback key.
var emptyKeyHex = []byte{
	0xd0, 0xd0, 0xec, 0x9c, 0x7d, 0x77, 0xd4, 0x3a,
	0xc5, 0x41, 0x87, 0xfa, 0x48, 0x18, 0xd1, 0x7f,
}

func sameBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func deriveChromiumKey(password []byte) []byte {
	return pbkdf2.Key(password, []byte("saltysalt"), 1, 16, sha1.New) //nolint:gosec // scheme mandated by Chromium
}

func spaces16() []byte {
	iv := make([]byte, aes.BlockSize)
	for i := range iv {
		iv[i] = ' '
	}
	return iv
}

// cbcDecrypt returns the raw decrypted bytes, or nil on bad input.
func cbcDecrypt(key, iv, payload []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	if len(payload) == 0 || len(payload)%aes.BlockSize != 0 {
		return nil
	}
	plain := make([]byte, len(payload))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, payload)
	return plain
}

// decryptCBCStrictPKCS7 decrypts and accepts only when the trailing bytes
// form valid PKCS#7 padding — strong evidence the key was correct.
func decryptCBCStrictPKCS7(key, payload []byte) ([]byte, bool) {
	plain := cbcDecrypt(key, spaces16(), payload)
	if plain == nil {
		return nil, false
	}
	s, ok := trimPKCS7Strict(plain)
	if !ok {
		return nil, false
	}
	return []byte(s), true
}

// trimPKCS7Strict returns (unpadded string, true) when the trailing bytes
// form valid PKCS#7 padding, or ("", false) otherwise. Strict: all padding
// bytes must equal the pad length.
func trimPKCS7Strict(plain []byte) (string, bool) {
	if len(plain) < 2 {
		return "", false
	}
	n := int(plain[len(plain)-1])
	if n == 0 || n > aes.BlockSize {
		return "", false
	}
	end := len(plain) - n
	if end < 0 {
		return "", false
	}
	for _, c := range plain[end:] {
		if int(c) != n {
			return "", false
		}
	}
	return string(plain[:end]), true
}

func chromiumSameSite(n int) string {
	switch n {
	case 1:
		return "no_restriction"
	case 2:
		return "lax"
	case 3:
		return "strict"
	default:
		return "unspecified"
	}
}

func chromiumPriority(n int) string {
	switch n {
	case 0:
		return "low"
	case 1:
		return "medium"
	case 2:
		return "high"
	default:
		return "medium"
	}
}

func formatChromiumTime(micros int64) string {
	if micros <= 0 {
		return ""
	}
	t := time.Unix(0, (micros-chromiumEpochDelta)*1000).UTC()
	if t.Year() < 2000 { // sanity: Chromium epochs never predate the browser
		return ""
	}
	return t.Format(time.RFC3339)
}

func copyToTemp(src string) (string, func(), error) {
	in, err := os.Open(src)
	if err != nil {
		return "", nil, err
	}
	defer in.Close()

	tmp, err := os.CreateTemp("", "cookie-dump-*.sqlite")
	if err != nil {
		return "", nil, err
	}
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", nil, err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", nil, err
	}
	return tmp.Name(), func() { os.Remove(tmp.Name()) }, nil
}
