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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as paddingAsym
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.exceptions import InvalidSignature

debug = False

def writeKeys(kr_fname, ku_fname, passwd, size=2048, backend=default_backend()):
  private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=size,
    backend=backend
  )

  # Generate public from private
  public_key = private_key.public_key()

  if debug:
      print("Private:", private_key)
      print("Public :", public_key)

  pem_kr1 = private_key.private_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PrivateFormat.PKCS8,
      encryption_algorithm=serialization.BestAvailableEncryption(passwd.encode())
  )

  # Generate pulbic un-encrypted key
  pem_ku1 = public_key.public_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PublicFormat.SubjectPublicKeyInfo
  )



  if debug:
    print("Private pem:", pem_kr1)
    print("Public pem :", pem_ku1)

  try:
    with open(kr_fname, 'w') as file:
     file.write(pem_kr1.decode("utf-8"))
     file.close()

  except IOError:
   print("Could not read file:", kr_fname)
   raise IOError
   return False

  try:
    with open(ku_fname, 'w') as file:
     file.write(pem_ku1.decode("utf-8"))
     file.close()

  except IOError:
   print("Could not read file:", ku_fname)
   raise IOError
   return False

  return private_key, public_key

kr_fname = "keystoreU2/krU2.pem"
ku_fname = "keystoreU2/kuU2.pem"
key_pass = "HELLO"

if not debug:
  #key_pass  = str.encode(getpass.getpass("Please input key password for User1:"))
  key_pass  = getpass.getpass("Please input key password for User2:")

print("Writing User2's keys")

try:
  writeKeys(kr_fname=kr_fname, ku_fname=ku_fname, passwd=key_pass)
except IOError:
  print("Writing keys failed")