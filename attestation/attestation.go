package attestation

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
)

// Self-signed batch attestation cert. Meets WebAuthn §8.2.1
// (C/O/OU/CN required) -- the old SoftU2F cert had no country field, so
// strict RPs silently dropped some registrations.

var attestationPrivateKeyPem = `-----BEGIN PRIVATE KEY-----
MHcCAQEEIGvPLCcs07XJtEbM2j/fGxZ6WM9hsE/3/r5nSqX/38K9oAoGCCqGSM49
AwEHoUQDQgAEDFpa+sZmLcYXt3/p1Luyde6FdY39zjSY13ymlPTEVRQ0UVQ+lxG+
hyJ+X06XxwpMnL80RAbI52Ye0NV70B7NjQ==
-----END PRIVATE KEY-----`

var attestationCertPem = `-----BEGIN CERTIFICATE-----
MIIB6zCCAZGgAwIBAgIEATUn1zAKBggqhkjOPQQDAjBjMQswCQYDVQQGEwJVUzER
MA8GA1UEChMIdHBtLWZpZG8xIjAgBgNVBAsTGUF1dGhlbnRpY2F0b3IgQXR0ZXN0
YXRpb24xHTAbBgNVBAMTFHRwbS1maWRvIGF0dGVzdGF0aW9uMCAXDTI2MDgyMjE2
NDk1M1oYDzIwNTYwODIzMTY0OTUzWjBjMQswCQYDVQQGEwJVUzERMA8GA1UEChMI
dHBtLWZpZG8xIjAgBgNVBAsTGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xHTAb
BgNVBAMTFHRwbS1maWRvIGF0dGVzdGF0aW9uMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEDFpa+sZmLcYXt3/p1Luyde6FdY39zjSY13ymlPTEVRQ0UVQ+lxG+hyJ+
X06XxwpMnL80RAbI52Ye0NV70B7NjaMxMC8wDgYDVR0PAQH/BAQDAgeAMA8GA1Ud
JQQIMAYGBFUdJQAwDAYDVR0TAQH/BAIwADAKBggqhkjOPQQDAgNIADBFAiEA/1lo
H0dFOq/0rXVWfeWOs0ae4vXVKtru+wvrq2QHn04CIEFhwFkHbjhjtBUP6oEZpgm/
Gpnjn4GBJRBrPLo95glK
-----END CERTIFICATE-----`

var (
	CertDer    []byte
	PrivateKey *ecdsa.PrivateKey
)

func init() {
	certDer, _ := pem.Decode([]byte(attestationCertPem))
	CertDer = certDer.Bytes

	privKeyDer, _ := pem.Decode([]byte(attestationPrivateKeyPem))

	var err error
	PrivateKey, err = x509.ParseECPrivateKey(privKeyDer.Bytes)
	if err != nil {
		panic(err)
	}
}
