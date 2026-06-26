"""
Script to generate an Elliptic Curve (EC) server certificate for an MQTT broker (Mosquitto).
Uses the previously generated Certificate Authority (CA) to sign the broker's certificate.
"""

import logging

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

# Import custom utility functions for certificate generation
from certs_utils import build_leaf_certificate, build_san, build_subject, load_ca, load_certs_dir, write_keypair

# Configure logging to prepend '[BROKER]' to all informational messages
logging.basicConfig(level=logging.INFO, format='[BROKER] - %(asctime)s - %(levelname)s - %(message)s')

# Default DNS names and IP addresses for the broker's Subject Alternative Name (SAN) extension
DEFAULT_DNS = ["mosquitto", "localhost", "gateway"]
DEFAULT_IPS = ["127.0.0.1"]

def generate_broker_cert() -> None:
    """
    Generates and saves a leaf certificate and private key specifically tailored 
    for an MQTT broker. The certificate is signed by the root CA and includes 
    Subject Alternative Names (SANs) for proper identity verification by clients.
    """
    # Determine the directory where certificates are stored
    certs_dir = load_certs_dir()
    
    # Load the Root CA private key and certificate required for signing the leaf certificate
    ca_key, ca_cert = load_ca(certs_dir)

    # Generate an Elliptic Curve private key using the SECP256R1 curve
    broker_key = ec.generate_private_key(ec.SECP256R1())
    
    # Construct the subject (identity) for the broker certificate
    subject = build_subject("mosquitto-broker")
    
    # Build the Subject Alternative Name (SAN) extension to secure specific hostnames and IPs.
    # It merges defaults with any additional entries provided via environment variables.
    san = build_san(DEFAULT_DNS, DEFAULT_IPS, "BROKER_CERT_DNS", "BROKER_CERT_IPS")
    
    # Define permitted operations for this key.
    # Brokers typically need digital signatures, key encipherment, and key agreement for secure TLS connections.
    key_usage = x509.KeyUsage(
        digital_signature=True,
        key_encipherment=True,
        key_agreement=True,
        content_commitment=False,
        data_encipherment=False,
        key_cert_sign=False,  # This is a leaf cert, so it cannot sign other certs
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )

    # Build and sign the leaf certificate
    broker_cert = build_leaf_certificate(
        ca_private_key=ca_key,
        ca_cert=ca_cert,
        leaf_private_key=broker_key,
        subject=subject,
        # Restrict the extended key usage to Server Authentication
        eku_oids=[ExtendedKeyUsageOID.SERVER_AUTH],
        key_usage=key_usage,
        san=san,
    )

    # Save the generated private key and certificate to disk
    key_path, crt_path = write_keypair(certs_dir, "broker", broker_key, broker_cert)

    # Log the successful creation and locations of the new files
    logging.info("Certificate generated in %s", certs_dir)
    logging.info("Private key : %s", key_path)
    logging.info("Certificate : %s", crt_path)

if __name__ == "__main__":
    generate_broker_cert()