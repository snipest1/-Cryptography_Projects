import os
import base64
from typing import Union

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from encodings.base64_codec import base64_encode
backend = default_backend()  # creates backend used
salt = os.urandom(16)
print(salt.hex())  # prints our salted hex value to be hashed for our password

kdf = PBKDF2HMAC(  # create our password key
    algorithm=hashes.SHA256(),
    length=16,
    salt=salt,
    iterations=100000,
    backend=backend)
idf = PBKDF2HMAC(  # create our iv value
    algorithm=hashes.SHA256(),
    length=16,
    salt=salt,
    iterations=100000,
    backend=backend)
passwd = b'password'  # hashed password
ivval = b'hello'
key = kdf.derive(passwd)
iv = idf.derive(ivval)
print(key.hex())
print(iv.hex())

# Create the cipher, and get an encryptor
cipher = Cipher(
    algorithm=algorithms.AES(key),
    mode=modes.CBC(iv),
    backend=backend)
encryptor = cipher.encryptor()

padder = padding.PKCS7(128).padder()  # PKCS7 padder to handle data of varying sizes
# Create our dummy data that will be encrypted
#mydata = b'12345678123456781'  # our 16 bytes of data
mydata = b'~/infile.txt'  # input data file for encryption
mydata2 = b'~/outfile.txt'

path = os.path.abspath(mydata)
path2 = os.path.abspath(mydata2)

# set the blocksize in bytes
blocksize = 16
# set the totalsize counter
totalsize = 0
# create a mutable array to hold the bytes
data = bytearray(blocksize)
file = open(mydata, 'rb')
file2 = open(mydata2, 'wb')
#path = os.path.abspath(fname)
#print(mydata)
mydata_pad = padder.update(mydata) + padder.finalize()

print(mydata_pad.hex())  # print padded dummy data
#ciphertext = encryptor.update(mydata) + encryptor.finalize()
ciphertext = encryptor.update(mydata_pad) + encryptor.finalize()  # padded ciphertext
print(ciphertext.hex())

#  Create our dummy that will be decrypted
decryptor = cipher.decryptor()  #  Decryptor object that decrypts ciphertext data
plaintext = decryptor.update(ciphertext) + decryptor.finalize()

# loop until done
while True:
 # read block from source file
 num = file.readinto(data)
 # adjust totalsize
 totalsize += num
 # print data, assuming text data
 #print(num,data)
 # use following if raw binary data
 # print(num,data.hex())
 # check if full block read
 if num == blocksize:
    # write full block to destination
    file2.write(data)
 else:
    # extract subarray
     data2: Union[int, bytearray] = data[0:num]
 # write subarray to destination and break loop
 file2.write(data2)
 break

 # close files (note will also flush destination file
 file.close()
 file2.close()
 # print totalsize
 print('read ', totalsize, ' bytes')
#print(plaintext.hex())
#print(base64_encode(key))
#print(base64_encode(iv))
#print(base64_encode(ciphertext))