package uvconfig

import (
	"path/filepath"
	"testing"
)

func TestDefaultWhenUnset(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "uv-config.json"))
	if err != nil {
		t.Fatal(err)
	}
	// No file yet -> default (Hello mode on).
	if !s.InternalUV() {
		t.Fatalf("expected default InternalUV=true, got false")
	}
}

func TestSetPersistsAndReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "uv-config.json")

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetInternalUV(false); err != nil {
		t.Fatal(err)
	}
	if s.InternalUV() {
		t.Fatal("expected InternalUV=false after SetInternalUV(false)")
	}

	// A stored explicit false must survive reopen and NOT revert to the
	// default-on.
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if s2.InternalUV() {
		t.Fatal("expected stored false to persist across reopen")
	}

	if err := s2.SetInternalUV(true); err != nil {
		t.Fatal(err)
	}
	s3, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if !s3.InternalUV() {
		t.Fatal("expected stored true to persist across reopen")
	}
}
