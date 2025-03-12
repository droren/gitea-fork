package x509

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/fullsailor/pkcs7" // Ensure you have this dependency.
)

// X509Signature holds the details extracted from an X.509 signature.
type X509Signature struct {
	Certificate *x509.Certificate
	Issuer      string
	Email       string
	Fingerprint string
}

// VerifyX509Signature takes the commit data and a signature text, parses the PKCS7
// signature, verifies it against the commit data using the provided root cert pool,
// and returns an X509Signature instance.
func VerifyX509Signature(commitData []byte, signatureText string, rootPool *x509.CertPool) (*X509Signature, error) {
	// Check for the expected S/MIME marker.
	if !strings.Contains(signatureText, "-----BEGIN SIGNED MESSAGE-----") {
		return nil, errors.New("signature does not appear to be an S/MIME (X.509) signature")
	}

	// Convert the ASCII-armored signature to bytes.
	sigBytes := []byte(signatureText)

	// Parse the PKCS7 structure.
	p7, err := pkcs7.Parse(sigBytes)
	if err != nil {
		return nil, err
	}

	// Verify the signature using the provided root certificate pool.
	// Note: pkcs7.VerifyWithChain will perform certificate chain verification.
	if err = p7.VerifyWithChain(rootPool); err != nil {
		return nil, err
	}

	// Ensure there is at least one signer.
	if len(p7.Signers) == 0 {
		return nil, errors.New("no signers found in the signature")
	}

	// For simplicity, consider the first signer certificate.
	signerCert := p7.Signers[0]

	// Optional: check that the signed content matches the commit data.
	// Depending on your signature format, p7.Content might be nil, so adapt accordingly.
	if p7.Content != nil && !bytes.Equal(commitData, p7.Content) {
		return nil, errors.New("commit data does not match signature content")
	}

	// Run explicit certificate chain verification.
	opts := x509.VerifyOptions{
		Roots: rootPool,
		// You can set the CurrentTime, DNSName, KeyUsages etc. here if needed.
	}
	if _, err = signerCert.Verify(opts); err != nil {
		return nil, err
	}

	// Extract email address from the certificate (assuming it is populated).
	email := ""
	if len(signerCert.EmailAddresses) > 0 {
		email = signerCert.EmailAddresses[0]
	}

	return &X509Signature{
		Certificate: signerCert,
		Issuer:      signerCert.Issuer.CommonName,
		Email:       email,
		Fingerprint: computeFingerprint(signerCert),
	}, nil
}

// computeFingerprint computes a SHA256 fingerprint of the certificate.
func computeFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}
