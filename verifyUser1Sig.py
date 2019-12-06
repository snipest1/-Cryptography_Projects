

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

# Length default 16
len = 16

# Iterations default 100000
itr = 100000

# function to generate the key
def keyGen(passwd, salt=os.urandom(16), backend=default_backend()):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=len,
        salt=salt,
        iterations=itr,
        backend=backend)
    key = kdf.derive(passwd)
    return key, salt

# function to generate IV
def ivGen(ivval, salt=os.urandom(16), backend=default_backend()):
    idf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=len,
        salt=salt,
        iterations=itr,
        backend=backend)
    iv = idf.derive(ivval)
    return iv, salt

# Create key cipher
def cipherGen(keyval, ivval, backend=default_backend()):
    cipher = Cipher(
        algorithm=algorithms.AES(keyval),
        mode=modes.CBC(ivval),
        backend=backend)
    return cipher

# decrypts file using public key
def decryptFile(fname0, fname1, keyPass, salt=os.urandom(16), blocksize=16):
    # set the totalsize counter
    totalsize = 0

    # create a mutable array to hold the bytes
    data = bytearray(blocksize)

    try:
        inFile = open(fname0, 'rb')
        filesize = os.stat(fname0).st_size
    except IOError:
        print("Could not read file:", fname0)
        return False

    try:
        outFile = open(fname1, 'wb')
    except IOError:
        print("Could not read file:", fname1)
        return False

    if debug:
        print("Opened both ", fname0, " and ", fname1)

    # To see if full block or need padding
    threshold = filesize - blocksize - 1

    if debug:
        print("Threshold:", threshold)

    key = keyGen(keyPass, salt)[0]
    iv = inFile.read(17)
    iv = iv[:16]

    if debug:
        print("Key is", key.hex())
        print("IV  is", iv.hex())

    while True:
        # read block from source file
        data = bytes(inFile.read(blocksize))
        num = blocksize
        # adjust totalsize
        totalsize += num

        if debug:
            print("\t     Num :", num)
            print("\t     Data:", data.hex())
            print("\tTotalsize:", totalsize)

        # Generate cipher, encryptor, and decryptor
        cipher = cipherGen(key, iv)
        decryptor = cipher.decryptor()

        # check if full block read
        if totalsize < threshold:
            # write full block to destination
            plaintext = decryptor.update(data) + decryptor.finalize()

            outFile.write(plaintext)
        else:
            # add padding to destination and break loop
            upadder = padding.PKCS7(128).unpadder()
            data_pad = decryptor.update(data) + decryptor.finalize()
            plaintext = upadder.update(data_pad)

            if debug:
                print("\t Plaintext before finalize:", plaintext)

            plaintext += upadder.finalize()

            if debug:
                print("\t Plaintext after finalize:", plaintext)

            outFile.write(plaintext)
            break

    # Keep reading blocks until none left
    # close files (note will also flush destination file
    inFile.close()
    outFile.close()
    return True

# Read keys from private and public keys
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
        print("PrivateTemp:", private_key_temp)
        print("PublicTemp :", public_key_temp)

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
        print("Private Key:", private_key)
        print("Public Key :", public_key)

    return private_key, public_key


def hashData(data, backend=default_backend()):
    hash256 = hashes.SHA256()
    hashed256 = hashes.Hash(hash256, backend)
    byteData = data
    hashed256.update(byteData)
    digest256 = hashed256.finalize()
    return digest256

# read signature from file
def readSig(sig_fname):
    # Depending on system, might have to set length
    # endLen = len(str.encode("-----END SIGNATURE-----"))
    endLen = 23

    if debug:
        print("Taking off:", endLen)

    try:
        with open(sig_fname, 'rb') as file:
            file.readline()
            sig_temp = file.read()
            sig_temp = sig_temp[:-endLen]
            sig_temp = base64.decodestring(sig_temp)
            file.close()
    except IOError:
        print("Could not read file:", sig_fname)
        raise IOError
        return False

    if debug:
        print("Signature Read:", sig_temp)  # No new lines

    return sig_temp


#######################
salt_fname = "salt.txt"
inputFile = "encodedU1.txt"
outputFile = "finalMsgU1.txt"
filePass_fname = "filePassU1.txt"

sigMessage_fname = "messageU1.sig"
sigFilePass_fname = "filepassU1.sig"

U1Cert_fname = "U1_cert.pem"

kr_fname = "keystoreU2/krU2.pem"
ku_fname = "keystoreU2/kuU2.pem"
key_pass = "HELLO"
if not debug:
    # key_pass  = str.encode(getpass.getpass("Please input key password for User2:"))
    key_pass = getpass.getpass("Please input key password for User2:")
#######################

print("Reading salt")
try:
    with open(salt_fname, "rb") as file:
        salt = file.read()
        file.close()
except IOError:
    print("Couldn't read ", salt_fname)

print("Reading public/private other User key")
try:
    private_keyOther, public_keyOther = readKeys(kr_fname=kr_fname, ku_fname=ku_fname, passwd=key_pass)
except IOError:
    print("Reading keys failed")

print("Reading User1 Cert")
try:
    with open(U1Cert_fname, "rb") as file:
        certificate = x509.load_pem_x509_certificate(
            data=file.read(),
            backend=default_backend()
        )
        file.close()
except IOError:
    print("Couldn't read ", U1Cert_fname)

print("Getting User1 public key")
public_keyU1 = certificate.public_key()

print("Getting encrypted filePass")
try:
    with open(filePass_fname, "rb") as file:
        filePassEncrypted = file.read()
        file.close()
except IOError:
    print("Couldn't write ", filePass_fname)

print("Decrypting filePass using privateKeyOther")
filePassPlain = private_keyOther.decrypt(
    filePassEncrypted,
    paddingAsym.PKCS1v15()
)

print("Hashing decrypted filePass")
digestFilePass = hashData(filePassPlain)

print("Reading file signature")
try:
    sigReadFile = readSig(sigFilePass_fname)
except IOError:
    print("Reading file pass signature failed")

print("Verifying file signature")
try:
    # Padding has to be lower level for this implementation
    public_keyU1.verify(
        signature=sigReadFile,
        data=digestFilePass,
        padding=paddingAsym.PKCS1v15(),
        #    padding=paddingAsym.PSS(
        #      mgf=paddingAsym.MGF1(hashes.SHA256()),
        #      salt_length=paddingAsym.PSS.MAX_LENGTH
        #    ),
        algorithm=utils.Prehashed(hashes.SHA256())
    )
    print("File Sig Verified.")
except InvalidSignature:
    print("Invalid file signature.")

print("Reading encrypted message")
try:
    with open(inputFile, "rb") as file:
        messageEncrypt = file.read()
        file.close()
except IOError:
    print("Couldn't read ", inputFile)

digestMessage = hashData(messageEncrypt)

print("Reading message signature")
try:
    sigReadMessage = readSig(sigMessage_fname)
except IOError:
    print("Reading message signature failed")

print("Verifying message signature")
try:
    public_keyU1.verify(
        signature=sigReadMessage,
        data=digestMessage,
        padding=paddingAsym.PKCS1v15(),
        #    padding=paddingAsym.PSS(
        #      mgf=paddingAsym.MGF1(hashes.SHA256()),
        #      salt_length=paddingAsym.PSS.MAX_LENGTH
        #    ),
        algorithm=utils.Prehashed(hashes.SHA256())
    )
    print("Message Sig Verified.")
    isVerified = True
except InvalidSignature:
    isVerified = False
    print("Invalid message signature.")

print("Decrypting file")
if isVerified:
    if decryptFile(fname0=inputFile, fname1=outputFile, keyPass=filePassPlain, salt=salt):
        print("Decrypt Success")
    else:
        print("Decrypt Fail")
        sys.exit()
else:
    print("Signature not verified, didn't decrypt")


