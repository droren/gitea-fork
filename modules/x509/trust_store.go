package x509

import (
	"crypto/x509"
	"io/fs"
	"os"
	"path/filepath"

	"code.gitea.io/gitea/modules/setting"
)

var RootCAs *x509.CertPool

// LoadTrustStore loads all .pem files from the given directory into the global CertPool.
func LoadTrustStore(dir string) error {
	pool := x509.NewCertPool()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(d.Name()) != ".pem" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		pool.AppendCertsFromPEM(data)
		return nil
	})
	if err != nil {
		return err
	}
	RootCAs = pool
	return nil
}

// LoadDefaultTrustStore loads certificates from the path configured in app.ini.
func LoadDefaultTrustStore() error {
	return LoadTrustStore(setting.X509.TrustStorePath)
}
