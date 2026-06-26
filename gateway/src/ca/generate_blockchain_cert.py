"""
Script to generate an Elliptic Curve (EC) client certificate for blockchain communication.
Uses the Certificate Authority (CA) generated previously to sign the client certificate.
"""

import logging
import os

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

# Import custom utility functions for certificate generation
from certs_utils import build_leaf_certificate, build_subject, load_ca, load_certs_dir, write_keypair

# Configure logging to prepend '[BLOCKCHAIN]' to all informational messages
logging.basicConfig(level=logging.INFO, format='[BLOCKCHAIN] - %(asctime)s - %(levelname)s - %(message)s')


def generate_blockchain_cert() -> None:
    """
    Generates and saves a leaf certificate and private key specifically tailored 
    for a blockchain node or client. The certificate is signed by the root CA.
    """
    # Determine the directory where certificates are stored
    certs_dir = load_certs_dir()
    
    # Retrieve the Common Name (CN) for the blockchain certificate, defaulting to "blockchain"
    common_name = os.getenv("BLOCKCHAIN_CERT_CN", "blockchain")
    
    # Load the Root CA private key and certificate required for signing
    ca_key, ca_cert = load_ca(certs_dir)

    # Generate an Elliptic Curve private key using the SECP256R1 curve.
    # This curve is highly standard and frequently used in blockchain/cryptography environments.
    client_key = ec.generate_private_key(ec.SECP256R1())
    
    # Construct the subject (identity) for this specific certificate
    subject = build_subject(common_name)

    # Define permitted operations for this key. 
    # For blockchain clients, digital signatures and key agreement are typically required.
    key_usage = x509.KeyUsage(
        digital_signature=True,
        key_encipherment=False,
        key_agreement=True,
        content_commitment=False,
        data_encipherment=False,
        key_cert_sign=False,  # This is a leaf cert, not a CA, so it cannot sign other certs
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )

    # Build and sign the leaf certificate
    client_cert = build_leaf_certificate(
        ca_private_key=ca_key,
        ca_cert=ca_cert,
        leaf_private_key=client_key,
        subject=subject,
        # Restrict the extended key usage to Client Authentication only
        eku_oids=[ExtendedKeyUsageOID.CLIENT_AUTH],
        key_usage=key_usage,
        san=None,  # No Subject Alternative Names (IPs/DNS) are needed for this specific cert
    )

    # Save the generated private key and certificate to disk
    key_path, crt_path = write_keypair(certs_dir, "blockchain", client_key, client_cert)

    # Log the successful creation and locations of the new files
    logging.info("Certificate generated in %s", certs_dir)
    logging.info("Private key : %s", key_path)
    logging.info("Certificate : %s", crt_path)


if __name__ == "__main__":
    generate_blockchain_cert()