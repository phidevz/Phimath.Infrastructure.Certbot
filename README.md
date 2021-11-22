# Phimath.Infrastructure.Certbot
Simple automation tool to optain DNS-validated Let's Encrypt certificates.

## Features
- Supports both Let's Encrypt Staging and Production, so you can test your settings without getting rate limited
- Works with Cloudflare DNS (**only** that for now!)
- Based on .NET 6, so it works crossplatform (even ARM)
- Persists your account registration for both staging and production
- Supports wildcard certificates
- Can be called via cronjob
- Supports both RSA and ECDSA
- Automatically exports to
  + PKCS12 (found with file extensions `.p12` or `.pfx`, often used on Windows Systems)
  + PEM (used with nginx or Apache webserver)
  + Base64 encoded public certificate

## License
Licensed under GPLv3. For more information, see https://github.com/phidevz/Phimath.Infrastructure.Certbot/blob/master/LICENSE.
