import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

backend = default_backend()

private_key = rsa.generate_private_key(  # generate the private key
public_exponent=65537,  # exponent is public key value
key_size=2048,  # the key size is the number of bits of the key
backend=backend)  # uses default OpenSSL backend

public_key = private_key.public_key()  # get the public key portion

password = "hello"
pem_kr = private_key.private_bytes(  # our private key
encoding=serialization.Encoding.PEM,  # Encoding in PEM (Privacy Enhanced Mail), base64 DER(Distinguished Encoding Rules
format=serialization.PrivateFormat.PKCS8,  # Format is PKCS#8 for private key serialization
encryption_algorithm=serialization.BestAvailableEncryption(password.encode()))  # Encryption provided by built-in algorithim

pem_ku = public_key.public_bytes(  # our public key
encoding=serialization.Encoding.PEM,
format=serialization.PublicFormat.SubjectPublicKeyInfo)

kr_fname = 'kr.pem'

ku_fname = 'ku.pem'
  # store private key to kr file
#Save pem_ku to ku.pem  # store public key to ku file
path = os.path.abspath(kr_fname)
path2 = os.path.abspath(ku_fname)
file2 = open(kr_fname, 'wb')
file2.write(pem_kr)
file2.close()
file = open(ku_fname, 'wb')
file.write(pem_ku)
file.close()
with open(kr_fname,'rb') as file:
    private_key = serialization.load_pem_private_key(
        data=file.read(),
        password=password.encode(),
        backend=backend)
with open(ku_fname,'rb') as file:
    public_key = serialization.load_pem_public_key(
        data=file.read(),
        backend=backend)

