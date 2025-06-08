# Trusted Certificate Store

Gitea can load additional trusted root certificates from a configurable directory. These
certificates will be used when verifying X.509 signatures.

Set the directory in `app.ini`:

```
[x509]
TRUST_STORE_PATH = custom/trust-certs
```

Administrators can manage the global certificate store from **Admin → Trusted Root Certificates**.
Users can manage their personal trusted certificates from **Settings → Trusted Root Certificates**.
