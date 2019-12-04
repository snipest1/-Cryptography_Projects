import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
from encodings.base64_codec import base64_encode, base64_decode

backend = default_backend()  # set our default backend
#mydata = b'abcdef123!!!!'  # our user data to be read

with open('user1_cert.pem', 'rb') as file:
    certificate = x509.load_pem_x509_certificate(
        data=file.read(),
        backend=backend)
public_key = certificate.public_key()
sig = certificate.signature
data = certificate.tbs_certificate_bytes
myhash = hashes.SHA256()  # Create and call SHA256 hash function
hasher = hashes.Hash(myhash, backend)  # create hash object

hasher.update(data)  # add data to message digest with update function

digest = hasher.finalize()  # finalize hash algorithim digest
pad = padding.PKCS1v15()

public_key.verify(  # verify signature method
    signature=sig,
    data=digest,
    padding=pad, algorithm=utils.Prehashed(myhash))
sig_fname = 'sig.pem'
