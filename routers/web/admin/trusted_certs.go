package admin

import (
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
	tplAdminTrustedCerts templates.TplName = "admin/trusted_certs"
)

func TrustedCerts(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("trusted_certs")
	ctx.Data["PageIsAdminTrustedCerts"] = true
	ctx.Data["Link"] = setting.AppSubURL + "/-/admin/trusted_certs"
	loadTrustedCertsData(ctx)
	ctx.HTML(http.StatusOK, tplAdminTrustedCerts)
}

func TrustedCertsPost(ctx *context.Context) {
	form := web.GetForm(ctx).(*forms.AddRootCertForm)
	ctx.Data["Title"] = ctx.Tr("trusted_certs")
	ctx.Data["PageIsAdminTrustedCerts"] = true
	ctx.Data["Link"] = setting.AppSubURL + "/-/admin/trusted_certs"
	dir := filepath.Join(setting.X509.TrustStorePath, "global")
	if ctx.HasError() {
		loadTrustedCertsData(ctx)
		ctx.HTML(http.StatusOK, tplAdminTrustedCerts)
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
	ctx.Redirect(setting.AppSubURL + "/-/admin/trusted_certs")
}

func DeleteTrustedCert(ctx *context.Context) {
	dir := filepath.Join(setting.X509.TrustStorePath, "global")
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
	ctx.JSONRedirect(setting.AppSubURL + "/-/admin/trusted_certs")
}

func loadTrustedCertsData(ctx *context.Context) {
	dir := filepath.Join(setting.X509.TrustStorePath, "global")
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
