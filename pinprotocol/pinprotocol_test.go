package pinprotocol

import (
	"bytes"
	"testing"
)

func TestSharedSecretAgreement(t *testing.T) {
	authenticator, err := NewKeyAgreement()
	if err != nil {
		t.Fatal(err)
	}
	platform, err := NewKeyAgreement()
	if err != nil {
		t.Fatal(err)
	}

	authX, authY := authenticator.PublicKeyXY()
	platX, platY := platform.PublicKeyXY()

	s1, err := authenticator.SharedSecret(platX, platY)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := platform.SharedSecret(authX, authY)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(s1, s2) {
		t.Fatalf("shared secrets differ: %x vs %x", s1, s2)
	}
	if len(s1) != 32 {
		t.Fatalf("expected 32 byte shared secret, got %d", len(s1))
	}
}

func TestSharedSecretInvalidPeerKey(t *testing.T) {
	ka, err := NewKeyAgreement()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ka.SharedSecret(make([]byte, 31), make([]byte, 32)); err == nil {
		t.Fatal("expected error for short peer X coordinate")
	}
	if _, err := ka.SharedSecret(make([]byte, 32), make([]byte, 0)); err == nil {
		t.Fatal("expected error for empty peer Y coordinate")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	plaintext := []byte("0123456789abcdef") // 16 bytes

	ct, err := Encrypt(secret, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Decrypt(secret, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("round trip mismatch: got %x want %x", pt, plaintext)
	}
}

func TestEncryptRejectsUnalignedPlaintext(t *testing.T) {
	secret := make([]byte, 32)
	if _, err := Encrypt(secret, []byte("not16")); err == nil {
		t.Fatal("expected error for non-block-aligned plaintext")
	}
}

func TestDecryptRejectsUnalignedOrEmptyCiphertext(t *testing.T) {
	secret := make([]byte, 32)
	if _, err := Decrypt(secret, nil); err == nil {
		t.Fatal("expected error for empty ciphertext")
	}
	if _, err := Decrypt(secret, make([]byte, 17)); err == nil {
		t.Fatal("expected error for unaligned ciphertext")
	}
}

func TestAuthenticateVerify(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	msg := []byte("hello world")

	tag := Authenticate(key, msg)
	if len(tag) != 16 {
		t.Fatalf("expected 16 byte tag, got %d", len(tag))
	}
	if !VerifyAuthenticate(key, msg, tag) {
		t.Fatal("expected tag to verify")
	}

	tampered := append([]byte{}, tag...)
	tampered[0] ^= 0xFF
	if VerifyAuthenticate(key, msg, tampered) {
		t.Fatal("tampered tag should not verify")
	}
	if VerifyAuthenticate(key, []byte("different message"), tag) {
		t.Fatal("tag for different message should not verify")
	}
}

func TestHashPIN(t *testing.T) {
	h1 := HashPIN("1234")
	h2 := HashPIN("1234")
	h3 := HashPIN("5678")

	if len(h1) != 16 {
		t.Fatalf("expected 16 byte hash, got %d", len(h1))
	}
	if !bytes.Equal(h1, h2) {
		t.Fatal("hash of same PIN should be deterministic")
	}
	if bytes.Equal(h1, h3) {
		t.Fatal("hash of different PINs should differ")
	}
}
