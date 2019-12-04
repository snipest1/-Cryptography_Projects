import os

from verify import expect,Not, Truthy, Falsy,Less,Greater
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
from encodings.base64_codec import base64_encode, base64_decode


backend = default_backend()  # set our default backend

blocksize = 16  # default block size to be read into bytearray
totalsize = 0
data = bytearray(blocksize)

#mydata = b'abcdef123!!!!'  # our user data to be read
mydata = b'/Users/timothysnipes/Desktop/PyCharmProjects/sample_projects/cryptoLab/infile.txt'  # input data file for encryption
mydata2 = b'/Users/timothysnipes/Desktop/PyCharmProjects/sample_projects/cryptoLab/outfile.txt'  # output data file for e
# create a mutable array to hold the bytes
data = bytearray(blocksize)
file = open(mydata, 'rb')
file2 = open(mydata2, 'wb')
#myhash = hashes.MD5()  # create MD5 hash
myhash = hashes.SHA256()  # Create and call SHA256 hash function
hasher = hashes.Hash(myhash, backend)  # create hash object

hasher.update(mydata)  # add data to message digest with update function

private_key = rsa.generate_private_key(  # generate the private key
public_exponent=65537,  # exponent is public key value
key_size=2048,  # the key size is the number of bits of the key
backend=backend)  # uses default OpenSSL backend

public_key = private_key.public_key()  # get the public key portion
digest = hasher.finalize()  # finalize hash algorithim digest
pem_ku = public_key.public_bytes(  # our public key
encoding=serialization.Encoding.PEM,
format=serialization.PublicFormat.SubjectPublicKeyInfo)

pad = padding.PSS(  # padding designed for padding signatures
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH
)
sig = private_key.sign(  # signs the private key
    data=digest,
    padding=pad,
    algorithm=utils.Prehashed(myhash))  # pass the hash object into Prehashed function


path_eninput = os.path.abspath(mydata)
path2_enoutput = os.path.abspath(mydata2)

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
