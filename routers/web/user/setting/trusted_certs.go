package setting

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/templates"
	"code.gitea.io/gitea/modules/web"
	gitea_x509 "code.gitea.io/gitea/modules/x509"
	"code.gitea.io/gitea/services/context"
	"code.gitea.io/gitea/services/forms"
)

const (
	tplSettingsTrustedCerts templates.TplName = "user/settings/trusted_certs"
)

func userCertDir(uid int64) string {
	return filepath.Join(setting.X509.TrustStorePath, "users", fmt.Sprint(uid))
}

func TrustedCerts(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("trusted_certs")
	ctx.Data["PageIsSettingsTrustedCerts"] = true
	ctx.Data["Link"] = setting.AppSubURL + "/user/settings/trusted_certs"
	loadTrustedCertsData(ctx, userCertDir(ctx.Doer.ID))
	ctx.HTML(http.StatusOK, tplSettingsTrustedCerts)
}

func TrustedCertsPost(ctx *context.Context) {
	form := web.GetForm(ctx).(*forms.AddRootCertForm)
	ctx.Data["Title"] = ctx.Tr("trusted_certs")
	ctx.Data["PageIsSettingsTrustedCerts"] = true
	ctx.Data["Link"] = setting.AppSubURL + "/user/settings/trusted_certs"
	dir := userCertDir(ctx.Doer.ID)
	if ctx.HasError() {
		loadTrustedCertsData(ctx, dir)
		ctx.HTML(http.StatusOK, tplSettingsTrustedCerts)
		return
	}
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		ctx.ServerError("MkdirAll", err)
		return
	}
	filename := filepath.Join(dir, form.Title+".pem")
	if err := os.WriteFile(filename, []byte(form.Content), 0o600); err != nil {
		ctx.ServerError("WriteFile", err)
		return
	}
	if err := gitea_x509.LoadDefaultTrustStore(); err != nil {
		ctx.ServerError("LoadTrustStore", err)
		return
	}
	ctx.Flash.Success(ctx.Tr("add_trusted_cert_success"))
	ctx.Redirect(setting.AppSubURL + "/user/settings/trusted_certs")
}

func DeleteTrustedCert(ctx *context.Context) {
	dir := userCertDir(ctx.Doer.ID)
	filename := ctx.FormString("file")
	if err := os.Remove(filepath.Join(dir, filename)); err != nil {
		ctx.ServerError("Remove", err)
		return
	}
	if err := gitea_x509.LoadDefaultTrustStore(); err != nil {
		ctx.ServerError("LoadTrustStore", err)
		return
	}
	ctx.Flash.Success(ctx.Tr("trusted_cert_deletion_success"))
	ctx.JSONRedirect(setting.AppSubURL + "/user/settings/trusted_certs")
}

func loadTrustedCertsData(ctx *context.Context, dir string) {
	_ = os.MkdirAll(dir, os.ModePerm)
	files, err := filepath.Glob(filepath.Join(dir, "*.pem"))
	if err != nil {
		ctx.ServerError("Glob", err)
		return
	}
	var names []string
	for _, f := range files {
		names = append(names, filepath.Base(f))
	}
	ctx.Data["CertFiles"] = names
}
