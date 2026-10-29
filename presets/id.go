package presets

import "fmt"

// ID is a preset ID as an application persists it, for example the strategy a
// user chose. It is stored as a JSON string (encoding.TextMarshaler); only the
// ID is stored, the options come from the catalog through Lookup. The empty ID
// means "no choice".
//
// Unmarshalling rejects malformed values but accepts well-formed IDs that the
// current catalog does not contain: a settings file written by another library
// version still loads, and Lookup reports the ID as not found, so the
// application can fall back (for example to discovery) instead of failing.
type ID string

// ParseID checks that s is empty or has the form of a preset ID: "s" (TCP) or
// "u" (UDP) followed by 10 lowercase hex digits.
func ParseID(s string) (ID, error) {
	if !wellFormed(s) {
		return "", fmt.Errorf("presets: malformed preset ID %q", s)
	}
	return ID(s), nil
}

func wellFormed(s string) bool {
	if s == "" {
		return true
	}
	if len(s) != 1+idHexLen || (s[0] != 's' && s[0] != 'u') {
		return false
	}
	for i := 1; i < len(s); i++ {
		if c := s[i]; !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

// String returns the ID.
func (id ID) String() string { return string(id) }

// MarshalText implements encoding.TextMarshaler; a malformed ID is an error.
func (id ID) MarshalText() ([]byte, error) {
	if !wellFormed(string(id)) {
		return nil, fmt.Errorf("presets: malformed preset ID %q", string(id))
	}
	return []byte(id), nil
}

// UnmarshalText implements encoding.TextUnmarshaler (see ParseID).
func (id *ID) UnmarshalText(b []byte) error {
	v, err := ParseID(string(b))
	if err != nil {
		return err
	}
	*id = v
	return nil
}

// Lookup resolves the ID in the current catalogs (see ByID). The empty ID is
// never found.
func (id ID) Lookup() (Match, bool) { return ByID(string(id)) }
