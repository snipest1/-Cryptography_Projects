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
from cryptography.exceptions import InvalidSignature

debug = False

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


def cipherGen(keyval, ivval, backend=default_backend()):
    cipher = Cipher(
        algorithm=algorithms.AES(keyval),
        mode=modes.CBC(ivval),
        backend=backend)
    return cipher


def encryptFile(fname0, fname1, keyPass, ivPass=os.urandom(len), salt=os.urandom(16), blocksize=16):
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

    if debug:
        print("Filesize is", filesize)

    try:
        outFile = open(fname1, 'wb')
    except IOError:
        print("Could not read file:", fname1)
        return False

    if debug:
        print("Opened both ", fname0, " and ", fname1)

    key = keyGen(keyPass, salt)[0]
    iv = ivGen(ivPass, salt)[0]
    if debug:
        print("Key is", key.hex())
        print("IV  is", iv.hex())

    # Put IV as first block in output file
    outFile.write(iv + str.encode(os.linesep))

    # loop until inFile is finished
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
            print("\tComparison", str(filesize - totalsize))

        # Generate cipher, encryptor, and decryptor
        cipher = cipherGen(key, iv)
        encryptor = cipher.encryptor()

        # check if read all the data
        # has to be >= because might be multiple of 16, have to add block
        # of padding after
        if num == blocksize and (filesize - totalsize) >= 0:
            # write full block to destination
            ciphertext = encryptor.update(data) + encryptor.finalize()

            if debug:
                print("\t* Writing:", ciphertext.hex())

            outFile.write(ciphertext)
        else:
            # add padding to destination and break loop
            padder = padding.PKCS7(128).padder()
            data_pad = padder.update(data) + padder.finalize()

            if debug:
                print("\tPaddedData:", data_pad.hex())

            ciphertext = encryptor.update(data_pad)
            ciphertext += encryptor.finalize()

            if debug:
                print("\t* Writing:", ciphertext.hex())

            outFile.write(ciphertext)
            break

    # Keep reading blocks until none left
    # close files (note will also flush destination file
    inFile.close()
    outFile.close()
    return True


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


def writeSig(sig_fname, digest, private_key):
    # This implementation uses lower padding for the verification
    # pad = paddingAsym.PSS(
    #                      mgf=paddingAsym.MGF1(hashes.SHA256()),
    #                      salt_length=paddingAsym.PSS.MAX_LENGTH
    #                      )

    pad = paddingAsym.PKCS1v15()

    if debug:
        print("Pad:", pad)

    sig = private_key.sign(
        data=digest,
        padding=pad,
        algorithm=utils.Prehashed(hashes.SHA256())
    )

    if debug:
        print("Sig Written:", sig)
        print("Encoded Sig:", base64.encodestring(sig))  # has \n included

    # Writing signature to .pem files
    try:
        with open(sig_fname, 'wb') as file:
            file.write(str.encode("-----BEGIN SIGNATURE-----\n"))
            file.write(base64.encodestring(sig))
            file.write(str.encode("-----END SIGNATURE-----"))
            file.close()
    except IOError:
        print("Could not read file:", sig_fname)
        raise IOError
        return False

    return sig


#######################
salt = os.urandom(16)
salt_fname = "salt.txt"
inputFile = "messageU1.txt"
outputFile = "encodedU1.txt"
filePass = os.urandom(16)
filePass_fname = "filePassU1.txt"

sigMessage_fname = "messageU1.sig"
sigFilePass_fname = "filepassU1.sig"

U2_fname = "U2_cert.pem"

kr_fname = "keystoreU1/krU1.pem"
ku_fname = "keystoreU1/kuU1.pem"
key_pass = "hello"
if not debug:
    # key_pass  = str.encode(getpass.getpass("Please input key password for User1:"))
    key_pass = getpass.getpass("Please input key password for User1:")
#######################

print("Reading User1 keys")
try:
    private_keyU1, public_keyU1 = readKeys(kr_fname=kr_fname, ku_fname=ku_fname, passwd=key_pass)
except IOError:
    print("Reading keys failed")

print("Reading User2's cert")
try:
    with open(U2_fname, "rb") as file:
        certificate = x509.load_pem_x509_certificate(
            data=file.read(),
            backend=default_backend()
        )
        file.close()
except IOError:
    print("Couldn't read ", U2_fname)

print("Geting public U2 from Cert")
public_keyU2 = certificate.public_key()

print("Encrypting filePass using public key Other")
filePassEncrypted = public_keyU2.encrypt(
    filePass,
    paddingAsym.PKCS1v15()
)

print("Writing salt")
try:
    with open(salt_fname, "wb") as file:
        file.write(salt)
        file.close()
except IOError:
    print("Couldn't write ", salt_fname)

print("Writing encrypted filePass")
try:
    with open(filePass_fname, "wb") as file:
        file.write(filePassEncrypted)
        file.close()
except IOError:
    print("Couldn't write ", filePass_fname)

print("Encrypting file using filePass")
if encryptFile(fname0=inputFile, fname1=outputFile, keyPass=filePass, salt=salt):
    print("Encrypt Success")
else:
    print("Encrypt Fail")
    sys.exit()

print("Reading encrypted message")
try:
    with open(outputFile, "rb") as file:
        messageEncrypt = file.read()
        file.close()
except IOError:
    print("Couldn't read ", outputFile)

print("Hashing encrypted message")
# Digest encrypted file
digestMessage = hashData(messageEncrypt)

print("Hashing filePass")
digestFilePass = hashData(filePass)

print("Writing message signature")
try:
    sigWriteMessage = writeSig(sigMessage_fname, digestMessage, private_keyU1)
except IOError:
    print("Writing message signature failed")

print("Writing file pass signature")
try:
    sigWriteFile = writeSig(sigFilePass_fname, digestFilePass, private_keyU1)
except IOError:
    print("Writing file pass signature failed")