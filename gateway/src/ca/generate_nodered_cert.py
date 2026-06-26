"""
Script to generate an Elliptic Curve (EC) client certificate specifically for Node-RED.
Uses the previously generated Root Certificate Authority (CA) to sign the client certificate,
allowing Node-RED to securely authenticate with other services (like the MQTT broker).
"""

import logging
import os

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

# Import custom utility functions for certificate and key management
from certs_utils import build_leaf_certificate, build_subject, load_ca, load_certs_dir, write_keypair

# Configure logging to prepend '[NODERED]' to all messages to easily trace output
logging.basicConfig(level=logging.INFO, format="[NODERED] - %(asctime)s - %(levelname)s - %(message)s")

def generate_nodered_cert() -> None:
    """
    Generates and saves a leaf certificate and private key tailored for a Node-RED client.
    The resulting certificate is restricted to Client Authentication usage.
    """
    # Determine the directory where certificates are stored and loaded from
    certs_dir = load_certs_dir()
    
    # Retrieve the Common Name (CN) for the Node-RED certificate, defaulting to "nodered"
    common_name = os.getenv("NODERED_CERT_CN", "nodered")
    
    # Load the Root CA private key and certificate required to sign this new leaf certificate
    ca_key, ca_cert = load_ca(certs_dir)

    # Generate an Elliptic Curve private key using the standard SECP256R1 curve
    client_key = ec.generate_private_key(ec.SECP256R1())
    
    # Construct the subject (identity) for the Node-RED certificate
    subject = build_subject(common_name)

    # Define permitted cryptographic operations for this specific key.
    # As a client, it needs digital signatures and key agreement capabilities.
    key_usage = x509.KeyUsage(
        digital_signature=True,
        key_encipherment=False,
        key_agreement=True,
        content_commitment=False,
        data_encipherment=False,
        key_cert_sign=False,  # This is an end-entity (leaf) certificate, so it cannot act as a CA
        crl_sign=False,
        encipher_only=False,
        decipher_only=False
    )

    # Build and sign the leaf certificate
    client_cert = build_leaf_certificate(
        ca_private_key=ca_key,
        ca_cert=ca_cert,
        leaf_private_key=client_key,
        subject=subject,
        # Restrict the Extended Key Usage (EKU) explicitly to Client Authentication
        eku_oids=[ExtendedKeyUsageOID.CLIENT_AUTH],
        key_usage=key_usage,
        san=None,  # No Subject Alternative Names (DNS/IPs) are required for this client cert
    )

    # Save the generated private key and certificate to disk with the base name "nodered"
    key_path, crt_path = write_keypair(certs_dir, "nodered", client_key, client_cert)

    # Log the successful creation and exact locations of the newly generated files
    logging.info("Certificate generated in %s", certs_dir)
    logging.info("Private key : %s", key_path)
    logging.info("Certificate : %s", crt_path)

if __name__ == "__main__":
    generate_nodered_cert()