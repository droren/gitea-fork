package asymkey

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"

	"code.gitea.io/gitea/models/db"
	"code.gitea.io/gitea/modules/timeutil"
)

// X509Cert represents a stored X.509 certificate for a user.
type X509Cert struct {
	ID          int64              `xorm:"pk autoincr"`
	OwnerID     int64              `xorm:"INDEX NOT NULL"`
	Subject     string             `xorm:"TEXT"`
	Issuer      string             `xorm:"TEXT"`
	Fingerprint string             `xorm:"UNIQUE VARCHAR(64)"`
	Content     string             `xorm:"MEDIUMTEXT NOT NULL"`
	CreatedUnix timeutil.TimeStamp `xorm:"created"`
}

func init() {
	db.RegisterModel(new(X509Cert))
}

// ParseAndValidateX509 parses a PEM encoded certificate and returns basic info.
func ParseAndValidateX509(pemData string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("invalid certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// Fingerprint returns the SHA256 fingerprint of the certificate.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}
