// Package residentstore persists the metadata needed to serve CTAP2
// discoverable (resident) credentials: which credential IDs exist for a
// given rpId, and the user they belong to. The actual private key material
// stays inside the opaque keyHandle blob produced by the Signer backend
// (tpm or memory) -- this store never sees key material, only the wrapped
// handle plus enough WebAuthn metadata to answer GetAssertion with an empty
// allowList.
package residentstore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type Credential struct {
	CredentialID []byte `json:"credential_id"`
	RPID         string `json:"rp_id"`
	UserID       []byte `json:"user_id"`
	UserName     string `json:"user_name"`
	KeyHandle    []byte `json:"key_handle"`
	SignCount    uint32 `json:"sign_count"`
}

type Store struct {
	path string
	mu   sync.Mutex
	// creds indexed by rpId, most-recently-created last.
	creds map[string][]Credential
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
	return filepath.Join(dir, "tpm-fido", "resident-credentials.json"), nil
}

func Open(path string) (*Store, error) {
	if path == "" {
		var err error
		path, err = defaultPath()
		if err != nil {
			return nil, err
		}
	}

	s := &Store{
		path:  path,
		creds: make(map[string][]Credential),
	}

	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return s, nil
	} else if err != nil {
		return nil, fmt.Errorf("open resident store: %w", err)
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(&s.creds); err != nil {
		return nil, fmt.Errorf("decode resident store: %w", err)
	}

	return s, nil
}

func (s *Store) persistLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("mkdir resident store dir: %w", err)
	}

	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create resident store tmp: %w", err)
	}

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s.creds); err != nil {
		f.Close()
		return fmt.Errorf("encode resident store: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("close resident store tmp: %w", err)
	}

	return os.Rename(tmp, s.path)
}

// Put stores or replaces (by rpId+userId) a discoverable credential.
func (s *Store) Put(c Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing := s.creds[c.RPID]
	replaced := false
	for i, e := range existing {
		if string(e.UserID) == string(c.UserID) {
			existing[i] = c
			replaced = true
			break
		}
	}
	if !replaced {
		existing = append(existing, c)
	}
	s.creds[c.RPID] = existing

	return s.persistLocked()
}

// ByRPID returns all discoverable credentials registered for rpId.
func (s *Store) ByRPID(rpID string) []Credential {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]Credential(nil), s.creds[rpID]...)
}

// IncrementSignCount bumps and persists the sign counter for a credential,
// identified by rpId+credentialId, returning the new count.
func (s *Store) IncrementSignCount(rpID string, credentialID []byte) (uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing := s.creds[rpID]
	for i, e := range existing {
		if string(e.CredentialID) == string(credentialID) {
			existing[i].SignCount++
			count := existing[i].SignCount
			return count, s.persistLocked()
		}
	}
	return 0, fmt.Errorf("credential not found for rpId=%s", rpID)
}

// RPIDs returns the rpId of every relying party with at least one
// discoverable credential, in no particular order.
func (s *Store) RPIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]string, 0, len(s.creds))
	for rpID, creds := range s.creds {
		if len(creds) > 0 {
			out = append(out, rpID)
		}
	}
	return out
}

// Count returns the total number of discoverable credentials across all
// relying parties.
func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := 0
	for _, creds := range s.creds {
		n += len(creds)
	}
	return n
}

// Delete removes a single credential, identified by rpId+credentialId.
// Returns an error if no matching credential exists.
func (s *Store) Delete(rpID string, credentialID []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing := s.creds[rpID]
	for i, e := range existing {
		if string(e.CredentialID) == string(credentialID) {
			s.creds[rpID] = append(existing[:i], existing[i+1:]...)
			if len(s.creds[rpID]) == 0 {
				delete(s.creds, rpID)
			}
			return s.persistLocked()
		}
	}
	return fmt.Errorf("credential not found for rpId=%s", rpID)
}
