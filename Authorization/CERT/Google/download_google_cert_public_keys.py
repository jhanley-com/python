##############################################################################
# Date Created: 2023-03-11
# Last Update:  2023-03-11
# https://www.jhanley.com
# Copyright (c) 2020, John J. Hanley
# Author: John J. Hanley
# License: MIT
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##############################################################################

"""
This program downloads the Google public X.509 certificates,
extracts the public key from the certificate and
saves each key to a PKCS #8 Public Key PEM format.

Usage:
	python download_google_cert_public_keys.py 
	python download_google_cert_public_keys.py URL
	
	Default URL: https://www.googleapis.com/oauth2/v1/certs

For each key in the returned JSON is written to a file.
The filename is "public_" + Key ID + "_cert.pem"
"""

import os
import sys
from base64 import b64decode
from datetime import datetime, timedelta
import requests
# PyCryptodome
# https://pycryptodome.readthedocs.io/
from Crypto.PublicKey import RSA

GOOGLE_CERT_URI = 'https://www.googleapis.com/oauth2/v1/certs'

debugControl = {
	# Enable with --debug as a commmand flag
	# Print the HTTP Status Code, Response Headers and Content
	'debugFlag': False,

	# Enable with --debugHeaders as a commmand flag
	# Print the HTTP Response Headers
	'debugHeadersFlag': False
}

def usage():
	"""
	Print program usage information
	"""
	print(f"Usage: {sys.argv[0]} [--help]")
	print(f"Usage: {sys.argv[0]} [--debug|--debugHeaders] [URL]")
	print(f"Default URL: {GOOGLE_CERT_URI}")

class colors:	# pylint: disable=too-few-public-methods
	"""
	ANSI Escape Sequences
	"""
	grey   = '\033[1;30m'
	red    = '\033[1;31m'
	green  = '\033[1;32m'
	yellow = '\033[1;33m'
	blue   = '\033[1;34m'
	purple = '\033[1;35m'
	cyan   = '\033[1;36m'
	white  = '\033[1;37m'
	# End ANSI color
	ENDC   = '\033[0m'

def statusText(msg):
	"""
	Print messages with color
	"""

	sys.stdout.flush()
	sys.stderr.flush()
	sys.stdout.write(f"{colors.yellow}{msg}{colors.ENDC}")

def errorText(msg):
	"""
	Print messages with color
	"""

	sys.stdout.flush()
	sys.stderr.flush()
	sys.stderr.write(f"{colors.red}{msg}{colors.ENDC}")

def make_filename(kid):
	"""
	The filename is "public_" + Key ID + "_cert.pem"
	"""
	return 'public_' + kid + '_cert.pem'

def base64urldecode(data):
	"""
	Base64 URL Decode
	Convert - to + and _ to /
	Append padding
	"""
	data = data.replace('-', '+')
	data = data.replace('_', '/')
	data += '==='
	return b64decode(data)

def parse_cache_control(headers):
	"""
	Parse the Date and Cache-Control headers and print the
	expiration date for the response. JSON Web Keys can be
	cached and this header indicates for how long.
	"""

	if not 'cache-control' in headers:
		return

	date = False

	if 'date' in headers:
		http_date = headers['date']
		date = datetime.strptime(http_date, '%a, %d %b %Y %H:%M:%S GMT')

	cc = headers['cache-control']

	values = cc.split(',')

	for value in values:
		value = value.strip()
		if 'max-age' in value:
			max_age = int(value.split('=')[1].strip())
			date += timedelta(seconds=max_age)
			hours = max_age / 3600
			msg = f"Response is valid for {max_age:,} seconds"
			msg += f" ({hours:.1f} hours)"
			if not date:
				msg += "\n"
			else:
				msg += f" - expires at {date} GMT\n"
			statusText(msg)

def print_response(response):
	"""
	Print information about the HTTP response
	"""
	if debugControl['debugFlag']:
		print("#################### RESPONSE STATUS #####################")
		print(response.status_code)
		print("#################### RESPONSE HEADERS ####################")
		for k,v in response.headers.items():
			print(f"{k+':':<24} {v}")
		print("#################### RESPONSE CONTENT ####################")
		print(response.content.decode('utf-8'))
		print("##########################################################")
	elif debugControl['debugHeadersFlag']:
		print("#################### RESPONSE HEADERS ####################")
		for k,v in response.headers.items():
			print(f"{k+':':<24} {v}")
		print("##########################################################")

def fetch_certs(url):
	"""
	Read data from the URL and process as JSON data
	"""

	errTitle = "Error: Cannot download data from CERT endpoint\n"

	try:
		headers = {'Accept': 'application/json'}
		response = requests.get(url, timeout=5, headers=headers)
		print_response(response)
		response.raise_for_status()
		j = response.json()
	except requests.exceptions.JSONDecodeError as ex:
		errorText(errTitle)
		errorText("Error processing response data as JSON\n")
		errorText(str(ex) + "\n")
		sys.exit(1)
	except requests.exceptions.ConnectionError as ex:
		errorText(errTitle)
		errorText("Connection Error\n")
		errorText(str(ex) + "\n")
		sys.exit(1)
	except requests.exceptions.Timeout as ex:
		errorText(errTitle)
		errorText("Connection Timeout\n")
		errorText(str(ex) + "\n")
		sys.exit(1)
	except requests.exceptions.HTTPError as ex:
		errorText(errTitle)
		errorText(str(ex) + "\n")
		sys.exit(1)
	except requests.exceptions.MissingSchema as ex:
		errorText(errTitle)
		errorText(str(ex) + "\n")
		sys.exit(1)

	parse_cache_control(response.headers)
	return j

def processCommandLine(url, debug):
	"""
	Process the command line
	"""

	for arg in sys.argv[1:]:
		if arg in ('-debug', '--debug'):
			debug['debugFlag'] = True
			continue

		if arg in ('-debugHeaders', '--debugHeaders'):
			debug['debugHeadersFlag'] = True
			continue

		if arg in ('-h', '-help', '--help'):
			usage()
			sys.exit(0)

		if arg.startswith('-'):
			usage()
			errorText("\n")
			errorText(f"Error: Unknown flag: {arg}\n")
			sys.exit(1)

		url = arg

	return url

def processCert(kid, pem_cert):
	"""
	Process each X.509 certificate
	"""
	if debugControl['debugFlag']:
		print("Processing Key ID:", kid)

	publicKey = RSA.import_key(pem_cert)

	filename = make_filename(kid)
	print("Saving Public Key:", filename)

	with open(filename, 'wb') as f:
		f.write(publicKey.exportKey('PEM'))

if __name__ == '__main__':
	os.system('color')

	endpoint = GOOGLE_CERT_URI

	endpoint = processCommandLine(endpoint, debugControl)

	certs = fetch_certs(endpoint)

	for keyid, cert in certs.items():
		processCert(keyid, cert)
