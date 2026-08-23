package attestation

import (
	"crypto/ecdsa"
	"crypto/x509"
	"testing"
)

// TestAttestationCertSpecCompliance makes sure the cert passes the §8.2.1
// subject checks strict RPs enforce at registration.
func TestAttestationCertSpecCompliance(t *testing.T) {
	cert, err := x509.ParseCertificate(CertDer)
	if err != nil {
		t.Fatalf("parse cert: %s", err)
	}

	if cert.Version != 3 {
		t.Errorf("attestation cert MUST be X.509 v3, got v%d", cert.Version)
	}

	if len(cert.Subject.Country) == 0 || cert.Subject.Country[0] == "" {
		t.Error("Subject-C (country) is required by §8.2.1; missing")
	}
	if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] == "" {
		t.Error("Subject-O (organization) is required by §8.2.1; missing")
	}
	if len(cert.Subject.OrganizationalUnit) == 0 ||
		cert.Subject.OrganizationalUnit[0] != "Authenticator Attestation" {
		t.Errorf("Subject-OU must be %q, got %q",
			"Authenticator Attestation", cert.Subject.OrganizationalUnit)
	}
	if cert.Subject.CommonName == "" {
		t.Error("Subject-CN is required by §8.2.1; missing")
	}

	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("cert public key is %T, want *ecdsa.PublicKey", cert.PublicKey)
	}
	if pub.Curve != PrivateKey.Curve {
		t.Error("cert key curve differs from private key curve")
	}
	if pub.X.Cmp(PrivateKey.X) != 0 || pub.Y.Cmp(PrivateKey.Y) != 0 {
		t.Error("certificate public key does not match embedded private key")
	}

	// CheckSignatureFrom won't take a non-CA parent; do it manually.
	if err := cert.CheckSignature(cert.SignatureAlgorithm,
		cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Errorf("self-signature invalid: %s", err)
	}

	if !cert.NotAfter.After(cert.NotBefore) {
		t.Error("cert validity window is inverted")
	}
}
