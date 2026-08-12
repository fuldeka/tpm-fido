// Package pinstore persists the CTAP2 PIN's hash and retry-counter state.
// It never stores the PIN itself, only left-16-bytes-of-SHA-256(PIN), the
// same value the platform sends over the wire during setPIN/changePIN.
package pinstore

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const maxRetries = 8

type state struct {
	PINHash     []byte `json:"pin_hash,omitempty"`
	RetriesLeft int    `json:"retries_left"`
}

type Store struct {
	path string
	mu   sync.Mutex
	s    state
}

func defaultPath() (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home dir: %w", err)
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "tpm-fido", "pin-state.json"), nil
}

func Open(path string) (*Store, error) {
	if path == "" {
		var err error
		path, err = defaultPath()
		if err != nil {
			return nil, err
		}
	}

	s := &Store{path: path, s: state{RetriesLeft: maxRetries}}

	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return s, nil
	} else if err != nil {
		return nil, fmt.Errorf("open pin store: %w", err)
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(&s.s); err != nil {
		return nil, fmt.Errorf("decode pin store: %w", err)
	}

	return s, nil
}

func (s *Store) persistLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("mkdir pin store dir: %w", err)
	}

	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create pin store tmp: %w", err)
	}

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s.s); err != nil {
		f.Close()
		return fmt.Errorf("encode pin store: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("close pin store tmp: %w", err)
	}

	return os.Rename(tmp, s.path)
}

// IsSet reports whether a PIN has been configured yet.
func (s *Store) IsSet() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.s.PINHash) > 0
}

// RetriesLeft returns the number of PIN attempts remaining before lockout.
func (s *Store) RetriesLeft() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.s.RetriesLeft
}

// SetPIN stores a new PIN hash unconditionally (used by the setPIN
// subcommand, which requires no prior PIN) and resets the retry counter.
func (s *Store) SetPIN(hash []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.s.PINHash = append([]byte(nil), hash...)
	s.s.RetriesLeft = maxRetries
	return s.persistLocked()
}

// Verify checks hash against the stored PIN hash, decrementing the retry
// counter on failure and resetting it on success. Returns (true, nil) on
// match, (false, nil) on mismatch, or a non-nil error if retries are
// already exhausted (locked out).
func (s *Store) Verify(hash []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.s.RetriesLeft <= 0 {
		return false, fmt.Errorf("pin locked out")
	}

	match := len(hash) == len(s.s.PINHash) && subtle.ConstantTimeCompare(hash, s.s.PINHash) == 1
	if match {
		s.s.RetriesLeft = maxRetries
	} else {
		s.s.RetriesLeft--
	}

	if err := s.persistLocked(); err != nil {
		return false, err
	}

	return match, nil
}
