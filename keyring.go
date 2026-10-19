package main

import (
	"github.com/godbus/dbus/v5"
)

// safeStorageKey retrieves the Chromium-family "Safe Storage" secret from the
// DBus Secret Service (GNOME Keyring / KWallet / KeePassXC), the programmatic
// equivalent of the article's `secret-tool lookup application chromium`.
//
// Secret struct layout matches org.freedesktop.Secret.Item.GetSecret's
// (o ay ay s) tuple exactly.
type secret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

const libsecretSchema = "chrome_libsecret_org_chromium_Chromium"

// safeStorageKey returns the raw keyring secret, or nil when it cannot be
// obtained (missing bus, locked collection, no entry). All failures are
// silent: callers redact undecryptable cookies instead of crash-looping.
func safeStorageKey(applications []string) []byte {
	conn, err := dbus.SessionBus()
	if err != nil {
		return nil
	}
	defer conn.Close()

	secrets := conn.Object("org.freedesktop.secrets", dbus.ObjectPath("/org/freedesktop/secrets"))

	// Open a "plain" session (no transport encryption needed: the bus is local).
	var out dbus.Variant
	var sessionPath dbus.ObjectPath
	err = secrets.Call("org.freedesktop.Secret.Service.OpenSession", 0,
		"plain", dbus.MakeVariant("")).Store(&out, &sessionPath)
	if err != nil {
		return nil
	}

	for _, app := range applications {
		if key, ok := searchAndRead(conn, secrets, sessionPath, map[string]string{
			"xdg:schema":  libsecretSchema,
			"application": app,
		}); ok {
			return key
		}
		if key, ok := searchAndRead(conn, secrets, sessionPath, map[string]string{
			"application": app,
		}); ok {
			return key
		}
	}
	return nil
}

// searchAndRead searches one attribute map and retrieves the secret from the
// first matching unlocked item.
func searchAndRead(conn *dbus.Conn, secrets dbus.BusObject, sessionPath dbus.ObjectPath,
	attributes map[string]string) ([]byte, bool) {
	items := searchItems(conn, secrets, attributes)
	return secretFromItem(conn, sessionPath, items)
}

// searchItems tolerates keyring implementations whose SearchItems reply shape
// differs from the spec (an extra return value breaks dbus.Store).
func searchItems(conn *dbus.Conn, secrets dbus.BusObject, attributes map[string]string) []dbus.ObjectPath {
	call := secrets.Call("org.freedesktop.Secret.Service.SearchItems", 0, attributes)
	var paths []dbus.ObjectPath
	if err := call.Store(&paths); err == nil {
		return paths
	}
	// Raw fallback: body[0] should be the array of object paths.
	if len(call.Body) > 0 {
		if p, ok := call.Body[0].([]dbus.ObjectPath); ok {
			return p
		}
	}
	return nil
}

func secretFromItem(conn *dbus.Conn, sessionPath dbus.ObjectPath, items []dbus.ObjectPath) ([]byte, bool) {
	for _, itemPath := range items {
		item := conn.Object("org.freedesktop.secrets", itemPath)

		// Unlock first when needed (GNOME Keyring normally has the login
		// collection open for the session; KeePassXC/KWallet may not).
		var locked bool
		if err := item.StoreProperty("org.freedesktop.Secret.Item.Locked", &locked); err == nil && locked {
			var unlocked []dbus.ObjectPath
			var prompted dbus.ObjectPath
			secrets := conn.Object("org.freedesktop.secrets", dbus.ObjectPath("/org/freedesktop/secrets"))
			if err := secrets.Call("org.freedesktop.Secret.Service.Unlock", 0, []dbus.ObjectPath{itemPath}).
				Store(&unlocked, &prompted); err != nil {
				continue
			}
			// A non-empty `prompted` path would require user interaction via
			// an OrgFreedesktopSecret.Prompt window; we do not open UI here.
			if prompted != dbus.ObjectPath("/") {
				continue
			}
		}

		var sec secret
		if err := item.Call("org.freedesktop.Secret.Item.GetSecret", 0, sessionPath).Store(&sec); err != nil {
			continue
		}
		if len(sec.Value) > 0 {
			return sec.Value, true
		}
	}
	return nil, false
}
