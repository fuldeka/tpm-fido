// Package pinprotocol implements CTAP2 PIN/UV Auth Protocol One (CTAP2 spec
// §6.5.6), the ECDH-based key agreement and PIN encryption scheme used by
// authenticatorClientPIN. Only the pieces this authenticator needs are
// implemented: key agreement, PIN encrypt/decrypt (AES-256-CBC, IV=0, no
// padding since PIN hashes are always exactly 16 or 32 bytes), and the
// left-16-bytes HMAC-SHA256 auth tag used for pinUvAuthParam.
package pinprotocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

// KeyAgreement holds this authenticator's per-boot ECDH keypair. Protocol 1
// reuses the same authenticator keypair across all platform key-agreement
// requests (unlike Protocol 2, which regenerates per getKeyAgreement call).
type KeyAgreement struct {
	priv *ecdh.PrivateKey
}

func NewKeyAgreement() (*KeyAgreement, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyAgreement{priv: priv}, nil
}

// PublicKeyXY returns the uncompressed public key's X and Y coordinates,
// for encoding as a COSE_Key in the getKeyAgreement response.
func (k *KeyAgreement) PublicKeyXY() (x, y []byte) {
	raw := k.priv.PublicKey().Bytes() // uncompressed point: 0x04 || X || Y
	x = raw[1:33]
	y = raw[33:65]
	return x, y
}

// SharedSecret performs ECDH with the platform's public key (given as raw
// X/Y coordinates from its COSE_Key) and derives the Protocol One shared
// secret: SHA-256(Z), where Z is the ECDH shared point's X coordinate.
func (k *KeyAgreement) SharedSecret(peerX, peerY []byte) ([]byte, error) {
	if len(peerX) != 32 || len(peerY) != 32 {
		return nil, errors.New("invalid peer public key coordinates")
	}

	uncompressed := make([]byte, 65)
	uncompressed[0] = 0x04
	copy(uncompressed[1:33], peerX)
	copy(uncompressed[33:65], peerY)

	peerPub, err := ecdh.P256().NewPublicKey(uncompressed)
	if err != nil {
		return nil, err
	}

	z, err := k.priv.ECDH(peerPub)
	if err != nil {
		return nil, err
	}

	sum := sha256.Sum256(z)
	return sum[:], nil
}

// Decrypt reverses Encrypt: AES-256-CBC with a zero IV, no padding (CTAP2
// Protocol One never pads; ciphertext length is always a multiple of 16
// because inputs are always 16 or 32-byte PIN hashes).
func Decrypt(sharedSecret, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("invalid ciphertext length")
	}

	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	return plaintext, nil
}

// Encrypt is the inverse of Decrypt, used to encrypt the pinUvAuthToken
// returned to the platform.
func Encrypt(sharedSecret, plaintext []byte) ([]byte, error) {
	if len(plaintext)%aes.BlockSize != 0 {
		return nil, errors.New("plaintext must be a multiple of the AES block size")
	}

	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

// Authenticate computes pinUvAuthParam = left 16 bytes of
// HMAC-SHA256(key, message), per Protocol One §6.5.6.
func Authenticate(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	sum := mac.Sum(nil)
	return sum[:16]
}

// VerifyAuthenticate checks a pinUvAuthParam against an expected key and
// message using constant-time comparison.
func VerifyAuthenticate(key, message, authParam []byte) bool {
	expected := Authenticate(key, message)
	return hmac.Equal(expected, authParam)
}

// HashPIN implements the CTAP2 "left 16 bytes of SHA-256(PIN)" PIN hash
// used both when the platform encrypts newPinHash for setPIN/changePIN and
// when the authenticator itself needs to compare against a stored hash.
func HashPIN(pin string) []byte {
	sum := sha256.Sum256([]byte(pin))
	return sum[:16]
}
