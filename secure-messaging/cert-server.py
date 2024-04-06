import os
from datetime import datetime, timedelta
from ipaddress import IPv4Address

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.base import (
    Certificate,
    CertificateSigningRequest,
    CertificateSigningRequestBuilder,
)
from cryptography.x509.oid import NameOID

CERT_VALIDITY = 24
CERT_DIR = "certificates/"

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
USER_SK = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
USER_PK = USER_SK.public_key()


class CA:
    """
    CA is responsible for writing and managing certificates

    :param CA_SK: CA's secret key
    :param CA_PK: CA's public key
    """

    CA_SK = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    CA_PK = CA_SK.public_key()

    def request_certificate(
        self, csr: x509.CertificateSigningRequest
    ) -> x509.Certificate:
        """
        1. Checks if certificate already exists
        2. if not, creates and signs it as a CA
        3. writes it to the DB

        :param csr:
        :param address:
        :return:
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

        # cert_builder.add_extension(
        #     x509.SubjectAlternativeName([x509.IPAddress(address)]), critical=True
        # )

        certificate = cert_builder.sign(
            private_key=self.CA_SK, algorithm=hashes.SHA256(), backend=default_backend()
        )

        self.write_to_file(certificate)
        return certificate

    def write_to_file(self, certificate: Certificate):
        """
        Writes the ceritificate to local storage in PEM format

        :param certificate: certificate to write
        """
        file_path = f"{certificate.subject}.pem"
        try:
            with open(os.path.join(CERT_DIR, file_path), "wb") as cert_file:
                cert_file.write(
                    certificate.public_bytes(encoding=serialization.Encoding.PEM)
                )
        except Exception as identifier:
            pass

    def check_exists(self, csr: x509.CertificateSigningRequest):
        """
        Checks if a certificate exists -- using the file path:
        `<user>.pem`

        :param csr:
        :param address:
        :return:
        :rtype:
        :return:
        :rtype:
        """
        certificate_filename = f"{csr.subject}.pem"
        if os.path.exists(os.path.join(CERT_DIR, certificate_filename)):
            existing_certificate = x509.load_pem_x509_certificate(
                b"certificate_filename"
            )
            if self.check_validity(existing_certificate):
                return existing_certificate
        else:
            return None

    def check_validity(self, certificate: x509.Certificate) -> bool:
        """
        Checks the validity of the certificate provided:
        1. time
        2. signature

        :param certificate: Certificate to check
        :return: False if invalid or True if valid
        :rtype: Boolean
        """
        # check dates
        if (
            certificate.not_valid_before > datetime.now()
            or certificate.not_valid_after < datetime.now()
        ):
            return False

        # check signature
        try:
            CA_PK.verify(
                signature=certificate.signature,
                data=certificate.tbs_certificate_bytes,
                padding=padding.PKCS1v15(),
                algorithm=hashes.SHA256(),
            )
        except InvalidSignature as e:
            print(e)
            return False

        return True

    def delete_certificate(self):
        pass


def create_csr():
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name(
            [
                x509.NameAttribute(x509.NameOID.COMMON_NAME, "shah"),
            ]
        )
    )

    csr = csr_builder.sign(
        private_key=USER_SK, algorithm=hashes.SHA256(), backend=default_backend()
    )

    return csr


def read_cert(certificate: x509.Certificate):
    # Extract the public key from the certificate
    public_key = certificate.public_key()

    # Convert the public key to a string representation
    public_key_str = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    print(
        f"Issuer: {certificate.issuer}, "
        f"Subject: {certificate.subject}, "
        f"Serial Number: {certificate.serial_number}, "
        f"Public Key: {public_key_str}"
    )

    pass


if __name__ == "__main__":
    csr = create_csr()
