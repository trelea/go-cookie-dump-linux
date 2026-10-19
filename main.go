package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Cookie is the shared output record for every supported browser.
type Cookie struct {
	Domain           string `json:"domain"`
	Name             string `json:"name"`
	Value            string `json:"value"`
	Encrypted        bool   `json:"encrypted"` // true when the stored value could not be decrypted
	Path             string `json:"path"`
	Secure           bool   `json:"secure"`
	HttpOnly         bool   `json:"httpOnly"`
	SameSite         string `json:"sameSite"`
	IsPersistent     bool   `json:"isPersistent,omitempty"` // Chromium-family only
	Priority         string `json:"priority,omitempty"`     // Chromium-family only
	CreationTime     string `json:"creationTime,omitempty"`
	LastAccessTime   string `json:"lastAccessTime,omitempty"`
	Expires          string `json:"expires,omitempty"`
	BaseDomain       string `json:"baseDomain,omitempty"`       // Firefox only (older schemas)
	OriginAttributes string `json:"originAttributes,omitempty"` // Firefox only
}

type Browser struct {
	ID            string   // chrome | chromium | brave | firefox | firefox-dev
	ChromiumPaths []string // candidate Cookies file locations, first existing one wins
	FirefoxRoots  []string // directories whose */cookies.sqlite subdirs are profiles
	KeyringApps   []string // Secret Service `application` attributes to probe
}

func home() string {
	h, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	return h
}

const braveFlatpakRoot = ".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser"
const chromiumFlatpakRoot = ".var/app/org.chromium.Chromium/config/chromium"

func browsers() map[string]Browser {
	h := home()
	return map[string]Browser{
		"chrome": {
			ID: "chrome",
			ChromiumPaths: []string{
				filepath.Join(h, ".config/google-chrome/Default/Cookies"),
			},
			KeyringApps: []string{"chrome"},
		},
		"chromium": {
			ID: "chromium",
			ChromiumPaths: []string{
				filepath.Join(h, ".config/chromium/Default/Cookies"),
				filepath.Join(h, chromiumFlatpakRoot, "Default/Cookies"),
			},
			KeyringApps: []string{"chromium"},
		},
		"brave": {
			ID: "brave",
			ChromiumPaths: []string{
				filepath.Join(h, ".config/BraveSoftware/Brave-Browser/Default/Cookies"),
				filepath.Join(h, braveFlatpakRoot, "Default/Cookies"),
			},
			KeyringApps: []string{"brave"},
		},
		"firefox": {
			ID: "firefox",
			FirefoxRoots: []string{
				filepath.Join(h, ".mozilla/firefox"),
				filepath.Join(h, ".var/app/org.mozilla.firefox/.mozilla/firefox"),
				filepath.Join(h, "snap/firefox/common/.mozilla/firefox"),
			},
		},
		"firefox-dev": {
			ID: "firefox-dev",
			FirefoxRoots: []string{
				filepath.Join(h, ".mozilla/firefox"),
				filepath.Join(h, ".var/app/org.mozilla.firefox/.mozilla/firefox"),
			},
		},
	}
}

func main() {
	browserFlag := flag.String("browser", "all", "chrome|chromium|brave|firefox|firefox-dev|all")
	flag.Parse()

	const outDir = "./out"
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		fatal("cannot create output directory: %v", err)
	}

	all := browsers()
	order := []string{"chrome", "chromium", "brave", "firefox", "firefox-dev"}
	var selected []string
	if strings.EqualFold(*browserFlag, "all") {
		selected = order
	} else {
		b, ok := all[strings.ToLower(*browserFlag)]
		if !ok {
			fatal("unknown browser %q (valid: %s, all)", *browserFlag, strings.Join(order, ", "))
		}
		selected = []string{b.ID}
	}

	anyFound := false
	for _, id := range selected {
		b := all[id]
		var cookies []Cookie
		var err error

		switch {
		case len(b.ChromiumPaths) > 0:
			cookies, err = readChromium(b)
		default:
			cookies, err = readFirefox(b)
		}
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Printf("[skip]    %-12s no cookie database found (browser not installed or unused)\n", b.ID)
				continue
			}
			fatal("reading %s cookies: %v", b.ID, err)
		}

		anyFound = true
		total := len(cookies)
		undecrypted := 0
		for _, c := range cookies {
			if c.Encrypted {
				undecrypted++
			}
		}

		file := filepath.Join(outDir, b.ID+"_cookies.json")
		data, err := json.MarshalIndent(cookies, "", "  ")
		if err != nil {
			fatal("marshaling %s: %v", b.ID, err)
		}
		if err := os.WriteFile(file, append(data, '\n'), 0o600); err != nil {
			fatal("writing %s: %v", b.ID, err)
		}

		fmt.Printf("[written] %-12s %d cookie(s) -> %s (decrypted: %d, redacted: %d)\n",
			b.ID, total, file, total-undecrypted, undecrypted)
	}

	if anyFound {
		fmt.Println("\nWARNING: these JSON files contain live session credentials.",
			"Treat them like passwords: keep them private and delete them when done.")
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
