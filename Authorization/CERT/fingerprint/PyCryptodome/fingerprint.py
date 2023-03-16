"""
This code reads an X.509 certificate and prints the SHA-1 fingerprint in hex
"""

import sys
import re
from Crypto.Hash import SHA1
from Crypto.IO import PEM

def get_fingerprint(fname):
	"""
	Read an X.509 certificate and return the SHA-1 fingerprint in hex
	"""

	with open(fname, "r", encoding="utf-8") as f:
		pem_data = f.read()

	r = re.compile(r"\s*-----BEGIN (.*)-----\s+")
	m = r.match(pem_data)
	marker = m.group(1)

	if marker != "CERTIFICATE":
		print("Error: Expected X.509 Certificate")
		sys.exit(1)

	der = PEM.decode(pem_data)

	fingerprint = SHA1.new(data=der[0]).hexdigest()

	# insert leading zero chars to make the string 40 digits
	while len(fingerprint) < 40:
		fingerprint = '0' + fingerprint

	return fingerprint

if __name__ == '__main__':
	filename = "cert1.pem"

	print(get_fingerprint(filename))
