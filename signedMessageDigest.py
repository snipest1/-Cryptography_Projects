import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
from encodings.base64_codec import base64_encode

backend = default_backend()  # set our default backend

blocksize = 16  # default block size to be read into bytearray
totalsize = 0
data = bytearray(blocksize)

mydata = b'abcdef123!!!!'  # our user data to be read
#num = mydata.readinto(data)  # read the user data into our byte array
#totalsize += num
#print(num, data)

#myhash = hashes.MD5()  # create MD5 hash
myhash = hashes.SHA256()  # Create and call SHA256 hash function
hasher = hashes.Hash(myhash, backend)  # create hash object

hasher.update(mydata)  # add data to message digest with update function

digest = hasher.finalize()  # finalize hash algorithim digest

private_key = rsa.generate_private_key(  # generate the private key
public_exponent=65537,  # exponent is public key value
key_size=2048,  # the key size is the number of bits of the key
backend=backend)  # uses default OpenSSL backend

pad = padding.PSS(  # padding designed for padding signatures
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH
)

sig = private_key.sign(  # signs the private key
    data=digest,
    padding=pad,
    algorithm=utils.Prehashed(myhash))  # pass the hash object into Prehashed function

sig_fname = 'sig.pem'

path = os.path.abspath(sig_fname)
file2 = open(sig_fname, 'wb')
file2.write(sig)
file2.close()
