package auth

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"

	user_model "code.gitea.io/gitea/models/user"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/setting"
)

// Ensure the struct implements the interface.
var (
	_ Method = &ClientCert{}
)

// ClientCert implements authentication using TLS client certificates.
type ClientCert struct{}

// Name represents the name of auth method
func (c *ClientCert) Name() string {
	return "client_cert"
}

// Verify authenticates based on TLS client certificates.
func (c *ClientCert) Verify(req *http.Request, w http.ResponseWriter, store DataStore, sess SessionStore) (*user_model.User, error) {
	if req.TLS == nil || len(req.TLS.PeerCertificates) == 0 {
		return nil, nil
	}
	cert := req.TLS.PeerCertificates[0]

	var user *user_model.User
	var err error

	if len(cert.EmailAddresses) > 0 {
		user, err = user_model.GetUserByEmail(req.Context(), cert.EmailAddresses[0])
		if err != nil && !user_model.IsErrUserNotExist(err) {
			log.Error("GetUserByEmail: %v", err)
			return nil, err
		}
	}
	if user == nil {
		username := cert.Subject.CommonName
		if username != "" {
			user, err = user_model.GetUserByName(req.Context(), username)
			if err != nil && !user_model.IsErrUserNotExist(err) {
				log.Error("GetUserByName: %v", err)
				return nil, err
			}
		}
	}

	if user == nil {
		return nil, nil
	}

	detector := newAuthPathDetector(req)
	if !detector.isAPIPath() && !detector.isAttachmentDownload() && !detector.isGitRawOrAttachOrLFSPath() {
		if sess != nil && (sess.Get("uid") == nil || sess.Get("uid").(int64) != user.ID) {
			handleSignIn(w, req, sess, user)
		}
	}
	log.Trace("ClientCert Authorization: Logged in user %-v", user)
	store.GetData()["EnableClientCert"] = setting.Service.EnableClientCertAuth
	return user, nil
}

// ParseCertificate allows building x509 certificate from header if needed.
func ParseCertificate(pemData string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("failed to parse certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}
