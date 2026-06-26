"""
Script to generate a Root Certificate Authority (CA).
This CA will be used to sign all other leaf certificates (e.g., broker, blockchain, clients) 
within the Smart MicroGrid system. It uses Elliptic Curve Cryptography (ECC) for strong security.
"""

import logging
import os

from cryptography.hazmat.primitives.asymmetric import ec

# Import custom utility functions for certificate generation
from certs_utils import build_root_ca_certificate, build_subject, load_certs_dir, write_keypair

# Configure logging to prepend '[CA]' to all informational messages to distinguish it from other scripts
logging.basicConfig(level=logging.INFO, format="[CA] - %(asctime)s - %(levelname)s - %(message)s")

def create_root_ca() -> None:
    """
    Generates a self-signed Root Certificate Authority (CA) and its associated private key.
    Creates the necessary output directory if it does not already exist.
    """
    # Determine the target directory for certificates
    certs_dir = load_certs_dir()
    
    # Ensure the directory exists; if not, create it safely without raising an error
    os.makedirs(certs_dir, exist_ok=True)

    # Generate an Elliptic Curve private key using the highly standard SECP256R1 curve
    ca_private_key = ec.generate_private_key(ec.SECP256R1())
    
    # Define the core identity (Subject) for this Root CA
    subject = build_subject("SmartMicroGrid-Root-CA")
    
    # Generate the self-signed X.509 Root CA certificate
    ca_cert = build_root_ca_certificate(ca_private_key, subject)

    # Save the newly generated CA private key and certificate to disk with the base name "ca"
    key_path, crt_path = write_keypair(certs_dir, "ca", ca_private_key, ca_cert)

    # Log the successful creation and the exact locations of the CA files
    logging.info("Root CA generated in %s", certs_dir)
    logging.info("Private key: %s", key_path)
    logging.info("Certificate: %s", crt_path)

if __name__ == "__main__":
    create_root_ca()