"""
Utility module for generating, loading, and managing X.509 certificates and private keys.
"""

import ipaddress
import logging
import os
import stat
from datetime import datetime, timedelta, timezone
from typing import Iterable, Sequence, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

# Default configuration values for certificate generation and management
DEFAULT_CERTS_PATH = "certs"
DEFAULT_VALIDITY_DAYS = 3650
DEFAULT_CLOCK_SKEW_SECONDS = 7200
DEFAULT_ORG = "MicroGrid"
DEFAULT_COUNTRY = "IT"

def get_env_int(name: str, default: int, minimum: int = 0) -> int:
    """
    Safely fetch an environment variable as an integer.
    Falls back to the default value if the variable is missing or invalid.
    """
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError:
        # Log a warning if the provided environment variable is not a valid integer
        logging.warning("[CERTS_UTILS] Invalid %s=%r, using default %d", name, raw, default)
        value = default
    # Ensure the returned value is not lower than the specified minimum
    return max(value, minimum)

def cert_validity_days() -> int:
    """Retrieve the certificate validity period in days from the environment."""
    return get_env_int("CERT_VALIDITY_DAYS", DEFAULT_VALIDITY_DAYS, 1)

def clock_skew_tolerance() -> timedelta:
    """
    Retrieve the clock skew tolerance from the environment.
    This is used to adjust the 'not_valid_before' time to prevent issues
    with out-of-sync system clocks.
    """
    return timedelta(seconds=get_env_int("CERT_CLOCK_SKEW_SECONDS", DEFAULT_CLOCK_SKEW_SECONDS, 0))

def parse_csv_env(name: str) -> list[str]:
    """Parse a comma-separated environment variable into a list of strings."""
    raw = os.getenv(name, "")
    return [item.strip() for item in raw.split(",") if item.strip()]

def load_certs_dir() -> str:
    """Get the target directory path for storing/loading certificates."""
    return os.getenv("CERTS_PATH", DEFAULT_CERTS_PATH)

def load_ca(certs_dir: str) -> Tuple[object, x509.Certificate]:
    """
    Load the Certificate Authority (CA) private key and certificate from disk.
    Raises a FileNotFoundError if they do not exist.
    """
    ca_key_path = os.path.join(certs_dir, "ca.key")
    ca_crt_path = os.path.join(certs_dir, "ca.crt")

    if not os.path.exists(ca_key_path) or not os.path.exists(ca_crt_path):
        raise FileNotFoundError(
            f"[CERTS_UTILS] CA files not found in {certs_dir}. Run generate_ca.py first"
        )
    
    # Load the CA's private key
    with open(ca_key_path, "rb") as fh:
        ca_key = serialization.load_pem_private_key(fh.read(), password=None)
    
    # Load the CA's public certificate
    with open(ca_crt_path, "rb") as fh:
        ca_crt = x509.load_pem_x509_certificate(fh.read())

    return ca_key, ca_crt

def build_subject(
        common_name: str,
        organization: str = DEFAULT_ORG,
        country: str = DEFAULT_COUNTRY
) -> x509.Name:
    """Construct an X.509 Subject Name object with CN, O, and C fields."""
    return x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, country),
        ]
    )

def build_san(
        default_dns: Iterable[str],
        default_ips: Iterable[str],
        dns_env: str,
        ips_env: str,
) -> x509.SubjectAlternativeName:
    """
    Build a Subject Alternative Name (SAN) extension.
    Merges default DNS/IP lists with additional entries provided via environment variables.
    """
    # Combine defaults with environment variables and remove duplicates
    dns_names = sorted(set(default_dns).union(parse_csv_env(dns_env)))
    ip_values = sorted(set(default_ips).union(parse_csv_env(ips_env)))

    entries: list[x509.GeneralName] = [x509.DNSName(dns) for dns in dns_names]

    # Convert IP string values to proper ipaddress objects
    for ip in ip_values:
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(ip)))
        except ValueError as exc:
            raise ValueError(f"[CERTS_UTILS] Invalid IP in {ips_env}: '{ip}'") from exc
    
    return x509.SubjectAlternativeName(entries)

def build_root_ca_certificate(private_key, subject: x509.Name) -> x509.Certificate:
    """
    Generate and sign a root Certificate Authority (CA) certificate.
    The certificate is self-signed using the provided private key.
    """
    now_utc = datetime.now(timezone.utc)
    # Apply clock skew tolerance to ensure immediate validity across systems
    not_before = now_utc - clock_skew_tolerance()

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)  # Issuer is the same as subject for root CAs
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(now_utc + timedelta(days=cert_validity_days()))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())  # Self-sign the root CA
    )

def build_leaf_certificate(
        ca_private_key,
        ca_cert: x509.Certificate,
        leaf_private_key,
        subject: x509.Name,
        eku_oids: Sequence[x509.ObjectIdentifier],
        key_usage: x509.KeyUsage,
        san: x509.SubjectAlternativeName | None = None,
) -> x509.Certificate:
    """
    Generate a leaf (end-entity) certificate signed by the Certificate Authority.
    Applies Extended Key Usage (EKU) and optionally Subject Alternative Names (SAN).
    """
    now_utc = datetime.now(timezone.utc)
    not_before = now_utc - clock_skew_tolerance()

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)  # Issuer is the CA
        .public_key(leaf_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(now_utc + timedelta(days=cert_validity_days()))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(key_usage, critical=True)
        .add_extension(x509.ExtendedKeyUsage(list(eku_oids)), critical=False)
    )

    # Append SAN extension if provided
    if san is not None:
        builder = builder.add_extension(san, critical=False)

    # Sign the leaf certificate with the CA's private key
    return builder.sign(ca_private_key, hashes.SHA256())

def write_private_key(path: str, private_key) -> None:
    """
    Write a private key to disk in PEM format.
    Sets strict file permissions (read/write for owner only) for security.
    """
    with open(path, "wb") as fh:
        fh.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    # Restrict file permissions to 600 (owner read/write)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)

def write_certificate(path: str, certificate: x509.Certificate) -> None:
    """Write an X.509 certificate to disk in PEM format."""
    with open(path, "wb") as fh:
        fh.write(certificate.public_bytes(serialization.Encoding.PEM))

def write_keypair(
        certs_dir: str,
        base_name: str,
        private_key,
        certificate: x509.Certificate
) -> tuple[str, str]:
    """
    Convenience function to write both a private key and its corresponding
    certificate to the specified directory.
    Returns a tuple of the paths to the written key and certificate files.
    """
    key_path = os.path.join(certs_dir, f"{base_name}.key")
    crt_path = os.path.join(certs_dir, f"{base_name}.crt")
    
    write_private_key(key_path, private_key)
    write_certificate(crt_path, certificate)
    
    return key_path, crt_path