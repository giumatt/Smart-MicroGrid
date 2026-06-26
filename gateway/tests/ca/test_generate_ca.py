from cryptography import x509
from cryptography.x509.oid import NameOID

import generate_ca

def test_create_root_ca_creates_files_and_valid_ca_cert(certs_dir):
    generate_ca.create_root_ca()

    key_path = certs_dir / "ca.key"
    crt_path = certs_dir / "ca.crt"

    assert key_path.exists()
    assert crt_path.exists()

    cert = x509.load_pem_x509_certificate(crt_path.read_bytes())

    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value

    assert cn == "SmartMicroGrid-Root-CA"
    assert cert.issuer == cert.subject
    assert basic_constraints.ca is True
