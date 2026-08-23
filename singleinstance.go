package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// instanceLock holds the flock for the process lifetime; never closed,
// so the kernel releases it automatically on exit or crash.
var instanceLock *os.File

func acquireSingleInstanceLock() error {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = os.TempDir()
	}
	f, err := os.OpenFile(filepath.Join(dir, "tpm-fido.lock"),
		os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("create lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return fmt.Errorf("another tpm-fido is already running")
	}
	instanceLock = f
	return nil
}
