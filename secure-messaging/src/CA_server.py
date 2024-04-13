import logging
import os
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.base import Certificate
from cryptography.x509.oid import NameOID

import helpers

CERT_VALIDITY = 24
CERT_DIR = "certificates/"

logging.basicConfig(
    filename="ca.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


class CA:
    """
    CA is responsible for writing and managing certificates
    :param sk_location: path to CA's secret key
    :param pk_location: path to CA's public key
    """

    def __init__(self, pk_location, sk_location) -> None:
        self.ca_sk = helpers.load_private_key_from_file(sk_location)
        self.ca_pk = helpers.load_public_key_from_file(pk_location)
        print(type(self.ca_sk))

    def request_cert(self, csr: x509.CertificateSigningRequest) -> x509.Certificate:
        """
        1. Checks if certificate already exists
        2. if not, creates and signs it as a CA
        3. writes it to the DB
        :param csr:
        :param address:
        :return:
        """
        logging.info(msg=f"request_cert REQUEST {csr.subject}")
        # TODO: check if cert already exists
        logging.info(msg=f"request_cert CREATE {csr.subject}")
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
        certificate = cert_builder.sign(
            private_key=self.ca_sk,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )
        logging.info(msg=f"request_cert SIGNED {csr.subject}")
        self.write_to_file(certificate)
        logging.info(msg=f"request_cert WRITTEN {csr.subject}")
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
        except Exception as e:
            logging.error(f"write_to_file {e}")

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
            self.ca_pk.verify(
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
