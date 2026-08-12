package residentstore

import (
	"bytes"
	"path/filepath"
	"testing"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "resident-credentials.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPutAndByRPID(t *testing.T) {
	s := openTemp(t)

	c := Credential{CredentialID: []byte("cred1"), RPID: "example.com", UserID: []byte("user1"), UserName: "alice"}
	if err := s.Put(c); err != nil {
		t.Fatal(err)
	}

	creds := s.ByRPID("example.com")
	if len(creds) != 1 || string(creds[0].CredentialID) != "cred1" {
		t.Fatalf("unexpected creds: %+v", creds)
	}
}

func TestPutDistinctUsersDoNotCollide(t *testing.T) {
	s := openTemp(t)

	a := Credential{CredentialID: []byte("credA"), RPID: "example.com", UserID: []byte("userA"), UserName: "alice"}
	b := Credential{CredentialID: []byte("credB"), RPID: "example.com", UserID: []byte("userB"), UserName: "bob"}

	if err := s.Put(a); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(b); err != nil {
		t.Fatal(err)
	}

	creds := s.ByRPID("example.com")
	if len(creds) != 2 {
		t.Fatalf("expected 2 distinct credentials, got %d: %+v", len(creds), creds)
	}
}

func TestPutSameUserReplaces(t *testing.T) {
	s := openTemp(t)

	first := Credential{CredentialID: []byte("cred1"), RPID: "example.com", UserID: []byte("user1"), UserName: "alice"}
	updated := Credential{CredentialID: []byte("cred1-new"), RPID: "example.com", UserID: []byte("user1"), UserName: "alice"}

	if err := s.Put(first); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(updated); err != nil {
		t.Fatal(err)
	}

	creds := s.ByRPID("example.com")
	if len(creds) != 1 {
		t.Fatalf("expected re-registration to replace, got %d creds", len(creds))
	}
	if !bytes.Equal(creds[0].CredentialID, []byte("cred1-new")) {
		t.Fatalf("expected replaced credential, got %+v", creds[0])
	}
}

func TestIncrementSignCount(t *testing.T) {
	s := openTemp(t)
	c := Credential{CredentialID: []byte("cred1"), RPID: "example.com", UserID: []byte("user1")}
	if err := s.Put(c); err != nil {
		t.Fatal(err)
	}

	n1, err := s.IncrementSignCount("example.com", []byte("cred1"))
	if err != nil {
		t.Fatal(err)
	}
	n2, err := s.IncrementSignCount("example.com", []byte("cred1"))
	if err != nil {
		t.Fatal(err)
	}
	if n1 != 1 || n2 != 2 {
		t.Fatalf("expected monotonic counter 1,2 got %d,%d", n1, n2)
	}

	if _, err := s.IncrementSignCount("example.com", []byte("nonexistent")); err == nil {
		t.Fatal("expected error incrementing unknown credential")
	}
}

func TestDeleteAndRPIDs(t *testing.T) {
	s := openTemp(t)
	c := Credential{CredentialID: []byte("cred1"), RPID: "example.com", UserID: []byte("user1")}
	if err := s.Put(c); err != nil {
		t.Fatal(err)
	}

	rpids := s.RPIDs()
	if len(rpids) != 1 || rpids[0] != "example.com" {
		t.Fatalf("unexpected RPIDs: %v", rpids)
	}

	if err := s.Delete("example.com", []byte("cred1")); err != nil {
		t.Fatal(err)
	}

	if len(s.ByRPID("example.com")) != 0 {
		t.Fatal("expected credential to be removed")
	}
	if len(s.RPIDs()) != 0 {
		t.Fatal("expected rpID to be pruned once its last credential is deleted")
	}

	if err := s.Delete("example.com", []byte("cred1")); err == nil {
		t.Fatal("expected error deleting already-removed credential")
	}
}

func TestPersistenceAcrossOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resident-credentials.json")

	s1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.Put(Credential{CredentialID: []byte("cred1"), RPID: "example.com", UserID: []byte("user1")}); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	creds := s2.ByRPID("example.com")
	if len(creds) != 1 || string(creds[0].CredentialID) != "cred1" {
		t.Fatalf("credential did not survive reopen: %+v", creds)
	}
}

func TestCount(t *testing.T) {
	s := openTemp(t)
	if s.Count() != 0 {
		t.Fatalf("expected 0, got %d", s.Count())
	}
	s.Put(Credential{CredentialID: []byte("c1"), RPID: "a.com", UserID: []byte("u1")})
	s.Put(Credential{CredentialID: []byte("c2"), RPID: "b.com", UserID: []byte("u2")})
	if s.Count() != 2 {
		t.Fatalf("expected 2, got %d", s.Count())
	}
}
