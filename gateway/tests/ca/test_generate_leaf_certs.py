import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import generate_broker_cert
import generate_ca
import generate_nodered_cert
import generate_provisioner_cert

def _load_cert(path):
    return x509.load_pem_x509_certificate(path.read_bytes())

def _get_san_values(cert):
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    dns_entries = {entry.value for entry in san if isinstance(entry, x509.DNSName)}
    ip_entries = {str(entry.value) for entry in san if isinstance(entry, x509.IPAddress)}
    return dns_entries, ip_entries

@pytest.mark.parametrize(
    "generator",
    [
        generate_broker_cert.generate_broker_cert,
        generate_provisioner_cert.generate_provisioner_cert,
        generate_nodered_cert.generate_nodered_cert,
    ],
)
def test_leaf_generators_fail_without_ca(certs_dir, generator):
    with pytest.raises(FileNotFoundError, match="CA files not found"):
        generator()

def test_generate_broker_cert_includes_expected_extensions_and_san(certs_dir, monkeypatch):
    generate_ca.create_root_ca()
    monkeypatch.setenv("BROKER_CERT_DNS", "edge-broker.local")
    monkeypatch.setenv("BROKER_CERT_IPS", "10.42.0.5")

    generate_broker_cert.generate_broker_cert()

    cert = _load_cert(certs_dir / "broker.crt")
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    dns_entries, ip_entries = _get_san_values(cert)

    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert cn == "mosquitto-broker"
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku
    assert {"mosquitto", "localhost", "gateway", "edge-broker.local"}.issubset(dns_entries)
    assert {"127.0.0.1", "10.42.0.5"}.issubset(ip_entries)

def test_generate_broker_cert_rejects_invalid_ip(certs_dir, monkeypatch):
    generate_ca.create_root_ca()
    monkeypatch.setenv("BROKER_CERT_IPS", "invalid-ip")

    with pytest.raises(ValueError, match="BROKER_CERT_IPS"):
        generate_broker_cert.generate_broker_cert()

def test_generate_provisioner_cert_includes_expected_extensions_and_san(certs_dir, monkeypatch):
    generate_ca.create_root_ca()
    monkeypatch.setenv("PROVISIONER_CERT_DNS", "prov-edge.local")
    monkeypatch.setenv("PROVISIONER_CERT_IPS", "10.10.10.10")

    generate_provisioner_cert.generate_provisioner_cert()

    cert = _load_cert(certs_dir / "provisioner.crt")
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    dns_entries, ip_entries = _get_san_values(cert)

    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert cn == "provisioner"
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku
    assert {"provisioner", "smg_provisioner", "localhost", "gateway", "prov-edge.local"}.issubset(dns_entries)
    assert {"127.0.0.1", "10.10.10.10"}.issubset(ip_entries)

def test_generate_provisioner_cert_rejects_invalid_ip(certs_dir, monkeypatch):
    generate_ca.create_root_ca()
    monkeypatch.setenv("PROVISIONER_CERT_IPS", "300.300.1.1")

    with pytest.raises(ValueError, match="PROVISIONER_CERT_IPS"):
        generate_provisioner_cert.generate_provisioner_cert()

def test_generate_nodered_cert_uses_env_cn_and_client_auth(certs_dir, monkeypatch):
    generate_ca.create_root_ca()
    monkeypatch.setenv("NODERED_CERT_CN", "nodered-test")

    generate_nodered_cert.generate_nodered_cert()

    cert = _load_cert(certs_dir / "nodered.crt")
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    assert cn == "nodered-test"
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku

    with pytest.raises(x509.ExtensionNotFound):
        cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)