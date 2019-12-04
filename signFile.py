import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
from encodings.base64_codec import base64_encode, base64_decode

backend = default_backend()  # set our default backend

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

pad = padding.PKCS1v15()
myhash = hashes.SHA256()
hasher = hashes.Hash(myhash,backend)
digest = hasher.finalize()
sig = private_key.sign(data=digest,
padding=pad, algorithm=utils.Prehashed(myhash))

try:
    public_key.verify(  # verify signature method
    signature=sig,
    data=digest,
    padding=pad, algorithm=utils.Prehashed(myhash))
    sig_fname = 'sig.pem'

    path = os.path.abspath(sig_fname)
    file2 = open(sig_fname, 'wb')  # writes message into bytes like object
    file2.write(sig)
    file2.close()

except:
    hasher.update(b"message to hash")  # update our message digest if signature is incorrect
    hasher.verify(b"incorrect signature") # exception thrown if signature is incorrect
else:
    print(base64_decode(sig))  # print base64 signature decoded into bytes
