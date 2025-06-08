package x509

import (
	"code.gitea.io/gitea/models/auth"
	"code.gitea.io/gitea/modules/json"
)

// Source holds configuration for X509 client certificate authentication.
type Source struct {
	auth.ConfigBase `json:"-"`

	AutoCreateUsers   bool
	AutoActivateUsers bool
	DefaultLanguage   string
}

func (cfg *Source) FromDB(bs []byte) error {
	return json.UnmarshalHandleDoubleEncode(bs, cfg)
}

func (cfg *Source) ToDB() ([]byte, error) {
	return json.Marshal(cfg)
}

func init() {
	auth.RegisterTypeConfig(auth.X509, &Source{})
}
