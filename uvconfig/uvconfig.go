// Package uvconfig persists user-facing authenticator behavior toggles that
// aren't part of the FIDO credential/PIN state proper. Right now that's just
// the "internal UV" (Windows-Hello-style) mode switch, but it's its own store
// so future toggles have a home that isn't tangled up with pinstore's
// security-sensitive hash/retry state.
package uvconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type state struct {
	// InternalUV, when true, makes the authenticator advertise built-in user
	// verification (uv:true + pinUvAuthToken + FIDO_2_1) so browsers drive
	// getPinUvAuthTokenUsingUvWithPermissions and we collect the PIN in our
	// own system dialog -- no browser PIN box. When false, we behave as a
	// plain clientPIN authenticator (the browser collects the PIN).
	//
	// Pointer so we can distinguish "never written" (nil -> apply default)
	// from an explicit stored false.
	InternalUV *bool `json:"internal_uv,omitempty"`
}

type Store struct {
	path string
	mu   sync.Mutex
	s    state
}

// defaultInternalUV is the value used when the config file doesn't exist yet
// or predates the InternalUV field. Hello mode is the intended default
// experience; users turn it off via the tray if a browser update ever breaks
// internal UV over HID.
const defaultInternalUV = true

func defaultPath() (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home dir: %w", err)
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "tpm-fido", "uv-config.json"), nil
}

func Open(path string) (*Store, error) {
	if path == "" {
		var err error
		path, err = defaultPath()
		if err != nil {
			return nil, err
		}
	}

	s := &Store{path: path}

	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return s, nil
	} else if err != nil {
		return nil, fmt.Errorf("open uv config: %w", err)
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(&s.s); err != nil {
		return nil, fmt.Errorf("decode uv config: %w", err)
	}

	return s, nil
}

func (s *Store) persistLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("mkdir uv config dir: %w", err)
	}

	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create uv config tmp: %w", err)
	}

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s.s); err != nil {
		f.Close()
		return fmt.Errorf("encode uv config: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("close uv config tmp: %w", err)
	}

	return os.Rename(tmp, s.path)
}

// InternalUV reports whether Hello mode is enabled, applying the default when
// the toggle was never explicitly written.
func (s *Store) InternalUV() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.s.InternalUV == nil {
		return defaultInternalUV
	}
	return *s.s.InternalUV
}

// SetInternalUV records the toggle and persists it.
func (s *Store) SetInternalUV(on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := on
	s.s.InternalUV = &v
	return s.persistLocked()
}
