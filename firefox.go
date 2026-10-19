package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// readFirefox reads cookies from every matching profile's cookies.sqlite.
//
// Firefox stores cookie values in plaintext ('value' column, no NSS/keyring
// involvement), so no decryption is required here. On Linux both regular
// Firefox and Firefox Developer Edition profile their default profiles under
// ~/.mozilla/firefox/; we route profiles to the right JSON file by their
// directory names (dev-edition profiles end in '.dev-edition-default' etc.).
func readFirefox(b Browser) ([]Cookie, error) {
	var profileDBs []string
	for _, root := range b.FirefoxRoots {
		matches, _ := filepath.Glob(filepath.Join(root, "*/cookies.sqlite"))
		for _, m := range matches {
			if wantsProfile(b.ID, m) {
				profileDBs = append(profileDBs, m)
			}
		}
	}
	if len(profileDBs) == 0 {
		return nil, os.ErrNotExist
	}

	var out []Cookie
	for _, dbPath := range profileDBs {
		cookies, err := readFirefoxProfile(dbPath)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(filepath.Dir(dbPath)), err)
		}
		out = append(out, cookies...)
	}
	return out, nil
}

// wantsProfile routes each discovered profile to the right target:
// 'firefox-dev' takes profiles whose directory marks a Developer Edition
// profile, 'firefox' takes everything else.
func wantsProfile(id, cookiePath string) bool {
	isDev := isDevEditionProfile(cookiePath)
	if id == "firefox-dev" {
		return isDev
	}
	return !isDev
}

func isDevEditionProfile(cookiePath string) bool {
	dir := filepath.Base(filepath.Dir(cookiePath)) // e.g. 57da8a1p.dev-edition-default
	return strings.Contains(dir, "dev-edition")
}

func readFirefoxProfile(dbPath string) ([]Cookie, error) {
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

	rows, err := db.Query(`SELECT * FROM moz_cookies`)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	// Column sets differ across schema versions (baseDomain was dropped in
	// schema 11), so bind every column dynamically by name.
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	values := make([]any, len(cols))
	scannable := make([]any, len(cols))
	for i := range values {
		scannable[i] = &values[i]
	}

	var out []Cookie
	for rows.Next() {
		if err := rows.Scan(scannable...); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		row := map[string]any{}
		for i, c := range cols {
			row[c] = values[i]
		}
		out = append(out, cookieFromFirefoxRow(row))
	}
	return out, rows.Err()
}

func cookieFromFirefoxRow(row map[string]any) Cookie {
	getString := func(key string) string {
		s, _ := row[key].(string)
		return s
	}
	getBool := func(key string) bool {
		n, _ := row[key].(int64)
		return n == 1
	}

	c := Cookie{
		Domain:           getString("host"),
		Name:             getString("name"),
		Value:            getString("value"),
		Path:             getString("path"),
		Secure:           getBool("isSecure"),
		HttpOnly:         getBool("isHttpOnly"),
		SameSite:         firefoxSameSite(asInt64(row["sameSite"])),
		Encrypted:        false, // Firefox stores cookie values in plaintext
		BaseDomain:       getString("baseDomain"),
		OriginAttributes: getString("originAttributes"),
		CreationTime:     formatFirefoxMicros(asInt64(row["creationTime"])),
		LastAccessTime:   formatFirefoxMicros(asInt64(row["lastAccessed"])),
		// Firefox 'expiry' is in seconds, unlike the PRTime microseconds above.
		Expires: formatFirefoxSeconds(asInt64(row["expiry"])),
	}
	return c
}

func asInt64(v any) int64 {
	if v == nil {
		return 0
	}
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	default:
		return 0
	}
}

func firefoxSameSite(n int64) string {
	// nsICookie.idl: SAMESITE_NONE=0, SAMESITE_LAX=1, SAMESITE_STRICT=2,
	// SAMESITE_UNSET=256.
	switch n {
	case 0:
		return "none"
	case 1:
		return "lax"
	case 2:
		return "strict"
	case 256:
		return "unspecified"
	default:
		return "unspecified"
	}
}

func formatFirefoxMicros(prTime int64) string {
	if prTime <= 0 {
		return ""
	}
	return time.Unix(0, prTime*1000).UTC().Format(time.RFC3339)
}

func formatFirefoxSeconds(seconds int64) string {
	if seconds <= 0 { // 0 = session cookie
		return ""
	}
	return time.Unix(seconds, 0).UTC().Format(time.RFC3339)
}
