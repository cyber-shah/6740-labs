from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERT_VALIDITY = 24

"""
-----------------------------------------------------------------------------

The server needs to be able to do the following:
1. Manage users and passwords (create, update and delete)
2. Authenticate users using SRP
3. Maintain Certificates (create, delete and update)

-------------------------------------------------------------------------------
"""

# step 1: create certificates
# step 2: maintain them
# step 3: srp
# step 4: manage users and passwords

key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)


def issue_certificate(csr, address):
    """
    Issues a certificate, as the CA for the CSR given.
    Also adds an address field to the certificate.

    Args:
        csr ():
        address ():

    Returns:

    """
    valid_to = datetime.now() + timedelta(hours=CERT_VALIDITY)

    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "server")]))
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now())
        .not_valid_after(valid_to)
    )
    cert_builder.add_extension(
        x509.SubjectAlternativeName([x509.IPAddress(address)]), critical=True
    )

    certificate = cert_builder.sign(
        private_key=key, algorithm=hashes.SHA256(), backend=default_backend()
    )
    return certificate
