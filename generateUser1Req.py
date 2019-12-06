##
# Create signin request for User 1
##
import os
import sys
import base64
import getpass
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as paddingAsym
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.exceptions import InvalidSignature

debug = True

# Length default 16
len = 16

# Iterations default 100000
itr = 100000

def keyGen(passwd, salt=os.urandom(16), backend=default_backend()):
  kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=len,
    salt=salt,
    iterations=itr,
    backend=backend)
  key = kdf.derive(passwd)
  return key, salt

def ivGen(ivval, salt=os.urandom(16), backend=default_backend()):
  idf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=len,
    salt=salt,
    iterations=itr,
    backend=backend)
  iv = idf.derive(ivval)
  return iv, salt

def readKeys(kr_fname, ku_fname, passwd, backend=default_backend()):
  # Reading keys for serrialization
  try:
    with open(kr_fname, 'rb') as file:
      private_key_temp = file.read()
      file.close()
  except IOError:
    print("Could not read file:", kr_fname)
    raise IOError
    return False

  try:
    with open(ku_fname, 'rb') as file:
      public_key_temp = file.read()
      file.close()
  except IOError:
    print("Could not read file:", ku_fname)
    raise IOError
    return False

  if debug:
    print("PrivateTemp:",private_key_temp)
    print("PublicTemp :",public_key_temp)

  private_key = serialization.load_pem_private_key(
    data=private_key_temp,
    password=passwd.encode(),
    backend=backend
  )

  public_key = serialization.load_pem_public_key(
    data=public_key_temp,
    backend=backend
  )

  if debug:
    print("Private Key:",private_key)
    print("Public Key :",public_key)

  return private_key, public_key

#######################
request_fname = "CSRRequest.pem"
kr_fname = "keystoreU1/krU1.pem"
ku_fname = "keystoreU1/kuU1.pem"
key_pass = "hello"
if not debug:
  #key_pass  = str.encode(getpass.getpass("Please input key password for User1:"))
  key_pass  = getpass.getpass("Please input key password for User1:")
#######################

print("Reading User1 keys")
try:
  private_keyU1, public_keyU1 = readKeys(kr_fname=kr_fname, ku_fname=ku_fname, passwd=key_pass)
except IOError:
  print("Reading keys failed")

builder = x509.CertificateSigningRequestBuilder()
builder = builder.subject_name(x509.Name([
  x509.NameAttribute(NameOID.COMMON_NAME, u'User1'),
]))

builder = builder.add_extension(
  x509.BasicConstraints(ca=False, path_length=None), critical=True,
)

request = builder.sign(
  private_keyU1, hashes.SHA256(), default_backend()
)


print("Writing request to file")
try:
  with open(request_fname, 'wb') as file:
    file.write(request.public_bytes(Encoding.PEM))
    file.close()
except IOError:
  print("Could not write to file:", request_fname)