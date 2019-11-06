import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

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

print(mydata)
print(digest)