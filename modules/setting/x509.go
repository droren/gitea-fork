package setting

import "code.gitea.io/gitea/modules/log"

var X509 = struct {
	TrustStorePath string `ini:"TRUST_STORE_PATH"`
}{
	TrustStorePath: "custom/trust-certs",
}

func loadX509From(rootCfg ConfigProvider) {
	sec := rootCfg.Section("x509")
	if err := sec.MapTo(&X509); err != nil {
		log.Fatal("Failed to map X509 settings: %v", err)
	}
}
