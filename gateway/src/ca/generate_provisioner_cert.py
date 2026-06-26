"""
Script to generate an Elliptic Curve (EC) server certificate for the Provisioner service.
Uses the previously generated Root Certificate Authority (CA) to sign the certificate,
allowing secure TLS communication for provisioning tasks.
"""

import logging

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

# Import custom utility functions for certificate generation
from certs_utils import build_leaf_certificate, build_san, build_subject, load_ca, load_certs_dir, write_keypair

# Configure logging to prepend '[PROVISIONER]' to all informational messages
logging.basicConfig(level=logging.INFO, format='[PROVISIONER] - %(asctime)s - %(levelname)s - %(message)s')

# Default DNS names and IP addresses for the provisioner's Subject Alternative Name (SAN) extension
DEFAULT_DNS = ["provisioner", "smg_provisioner", "localhost", "gateway"]
DEFAULT_IPS = ["127.0.0.1"]

def generate_provisioner_cert() -> None:
    """
    Generates and saves a leaf certificate and private key specifically tailored 
    for the provisioner service. The certificate includes Server Authentication 
    and Subject Alternative Names (SANs) for proper identity verification.
    """
    # Determine the directory where certificates are stored
    certs_dir = load_certs_dir()
    
    # Load the Root CA private key and certificate required for signing
    ca_key, ca_cert = load_ca(certs_dir)

    # Generate an Elliptic Curve private key using the SECP256R1 curve
    provisioner_key = ec.generate_private_key(ec.SECP256R1())
    
    # Construct the subject (identity) for the provisioner certificate
    subject = build_subject("provisioner")
    
    # Build the Subject Alternative Name (SAN) extension to secure specific hostnames and IPs.
    # Merges defaults with any additional entries provided via environment variables.
    san = build_san(DEFAULT_DNS, DEFAULT_IPS, "PROVISIONER_CERT_DNS", "PROVISIONER_CERT_IPS")

    # Define permitted operations for this key.
    # Server certificates typically require digital signatures, key encipherment, and key agreement for TLS.
    key_usage = x509.KeyUsage(
        digital_signature=True,
        key_encipherment=True,
        key_agreement=True,
        content_commitment=False,
        data_encipherment=False,
        key_cert_sign=False,  # This is an end-entity (leaf) certificate, so it cannot act as a CA
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )

    # Build and sign the leaf certificate
    provisioner_cert = build_leaf_certificate(
        ca_private_key=ca_key,
        ca_cert=ca_cert,
        leaf_private_key=provisioner_key,
        subject=subject,
        # Restrict the Extended Key Usage (EKU) explicitly to Server Authentication
        eku_oids=[ExtendedKeyUsageOID.SERVER_AUTH],
        key_usage=key_usage,
        san=san,
    )

    # Save the generated private key and certificate to disk with the base name "provisioner"
    key_path, crt_path = write_keypair(certs_dir, "provisioner", provisioner_key, provisioner_cert)

    # Log the successful creation and exact locations of the newly generated files
    logging.info("Certificate generated in %s", certs_dir)
    logging.info("Private key : %s", key_path)
    logging.info("Certificate : %s", crt_path)

if __name__ == "__main__":
    generate_provisioner_cert()