import os, datetime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID

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

kr_fname = 'kr.pem'  # private key filename

ku_fname = 'ku.pem'  # public key filename
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

# Create subject and issuer of the certificate as the same person
subject = issuer = x509.Name([
x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Florida"),
x509.NameAttribute(NameOID.LOCALITY_NAME, u"Coral Gables"),
x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"University of Miami"),
x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"ECE Dept"),
x509.NameAttribute(NameOID.COMMON_NAME, u"User 1"),])

# Create a certificate builder object
builder = x509.CertificateBuilder()

# Set the subject and issuer
builder = builder.subject_name(subject)
builder = builder.issuer_name(issuer)

# Set the date
builder = builder.not_valid_before(datetime.datetime.today() - datetime.timedelta(days=1))
builder = builder.not_valid_after(datetime.datetime(2019, 11, 23))

# Set random serial number
builder = builder.serial_number(x509.random_serial_number())

# Add the public key
builder = builder.public_key(public_key)

# Add the basic extensions
builder = builder.add_extension(
x509.BasicConstraints(ca=False, path_length=None), critical=True,)

# Sign the certificate
certificate = builder.sign(
    private_key=private_key, algorithm=hashes.SHA256(),
    backend=default_backend())

# Save the certificate
cert_name = 'user1_cert.pem'  # user1 certificate filename
with open(cert_name, 'wb') as file:
    file.write(certificate.public_bytes(serialization.Encoding.PEM))

    print(cert_name)