# Download Google public X.509 certificates and convert to RSA public keys

## Release Date
March 12, 2023

---
## Program License

MIT Licensed. Refer to [copyright.txt](copyright.txt) and [LICENSE](LICENSE) for details.

---
## Program Description

Google publishes public keys in two formats: X.509 certificates and as JSON Web Keys (JWKS). This program downloads the X.509 certificates and writes each one as a RSA public key in PKCS #8 PEM format.

The public key is required to verify tokens signed by one of Google's private keys. An example token is the OIDC Identity Token. [Google Identity Tokens](https://cloud.google.com/docs/authentication/token-types#id)

The Google CERT endpoint for Google public keys is [https://www.googleapis.com/oauth2/v1/certs](https://www.googleapis.com/oauth2/v1/certs).

---
## Usage

`python download_google_cert_public_keys.py [OPTIONS] [URL]`

---
### OPTIONS
| Flag             | Description                                              |
|------------------|----------------------------------------------------------|
| -h, --help       | Display help text                                        |
| --debug          | Enable Debug Mode                                        |
| --debugHeaders   | Print the HTTP response headers                          |
| URL              | HTTP endpoint to download the X.509 certificates         |

---
### Notes

Refer to the related code that processes [JSON Web Keys](../../JWKS/Google).

---
## Requirements

### Python
This software has been tested with Python 3.11.

### Third-party Libraries
This software depends on the [PyCryptodome](https://pypi.org/project/pycryptodome/) library. Tested with version 3.17.

---
## Configure

`pip install pycryptodome`

---
## Known Issues
- None

---
## Known Bugs
- None
