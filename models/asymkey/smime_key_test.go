package asymkey

import (
	"testing"
	"time"

	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"

	"github.com/stretchr/testify/assert"
)

// generateTestCertificate creates a self-signed certificate for testing.
func generateTestCertificate() ([]byte, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test User",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	return derBytes, priv, nil
}

// TestParseSMIMECertificate tests parsing of an S/MIME certificate.
func TestParseSMIMECertificate(t *testing.T) {
	certDER, _, err := generateTestCertificate()
	assert.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	assert.NoError(t, err)
	assert.Equal(t, "Test User", cert.Subject.CommonName)
}

// TestVerifySMIMESignature tests verification of an S/MIME signature.
func TestVerifySMIMESignature(t *testing.T) {
	certDER, priv, err := generateTestCertificate()
	assert.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	assert.NoError(t, err)

	message := []byte("Test message")
	hashed := sha256.Sum256(message)

	signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
	assert.NoError(t, err)

	err = rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, hashed[:], signature)
	assert.NoError(t, err)
}

// TestLoadSMIMECertificateFromPEM tests loading an S/MIME certificate from a PEM file.
func TestLoadSMIMECertificateFromPEM(t *testing.T) {
	certDER, _, err := generateTestCertificate()
	assert.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	block, _ := pem.Decode(certPEM)
	assert.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)

	cert, err := x509.ParseCertificate(block.Bytes)
	assert.NoError(t, err)
	assert.Equal(t, "Test User", cert.Subject.CommonName)
}
