# Download Google JSON Web Keys and convert to RSA public keys

## Release Date
March 12, 2023

---
## Program License

MIT Licensed. Refer to [copyright.txt](copyright.txt) and [LICENSE](LICENSE) for details.

---
## Program Description

Google publishes public keys in two formats: X.509 certificates and as JSON Web Keys (JWKS). This program downloads the JWKS keys and writes each one as a RSA public key in PKCS #8 PEM format.

The public key is require to verify tokens signed by one of Google's private keys. An example token is the OIDC Identity Token. [Google Identity Tokens](https://cloud.google.com/docs/authentication/token-types#id)

The Google JWKS endpoint for Google public keys is [https://www.googleapis.com/oauth2/v3/certs](https://www.googleapis.com/oauth2/v3/certs).

---
## Usage

`python download_google_jwks_public_keys.py [OPTIONS] [URL]`

---
### OPTIONS
| Flag             | Description                                              |
|------------------|----------------------------------------------------------|
| -h, --help       | Display help text                                        |
| --debug          | Enable Debug Mode                                        |
| --debugHeaders   | Print the HTTP response headers                          |
| URL              | HTTP endpoint to download the JSON Web Key Set (JWKS)    |

---
### Notes

The JWK format is defined by [RFC7517](https://www.rfc-editor.org/rfc/rfc7517). Many vendors use JWKS to publish public keys.

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
- Only supports RSA keys. At this time, Google does not use 'EC' or 'oct' cryptographic algorithms. Refer to [RFC7518](https://www.rfc-editor.org/rfc/rfc7518#page-28)

---
## Known Bugs
 - None
