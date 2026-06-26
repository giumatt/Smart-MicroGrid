import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

import certs_utils as cu

def test_get_env_int_invalid_returns_default(monkeypatch):
    monkeypatch.setenv("TEST_INT", "not-a-number")
    assert cu.get_env_int("TEST_INT", 42) == 42

def test_get_env_int_applies_minimum(monkeypatch):
    monkeypatch.setenv("TEST_INT", "-12")
    assert cu.get_env_int("TEST_INT", 99, minimum=0) == 0

def test_parse_csv_env_trims_and_filters_empty(monkeypatch):
    monkeypatch.setenv("CSV_VALUES", " alpha, ,beta ,, gamma ")
    assert cu.parse_csv_env("CSV_VALUES") == ["alpha", "beta", "gamma"]

def test_build_san_merges_defaults_and_env(monkeypatch):
    monkeypatch.setenv("BROKER_CERT_DNS", "edge.local,localhost")
    monkeypatch.setenv("BROKER_CERT_IPS", "10.0.0.10")

    san = cu.build_san(
        default_dns=["localhost", "gateway"],
        default_ips=["127.0.0.1"],
        dns_env="BROKER_CERT_DNS",
        ips_env="BROKER_CERT_IPS",
    )

    dns_entries = {
        entry.value for entry in san if isinstance(entry, x509.DNSName)
    }
    ip_entries = {
        str(entry.value) for entry in san if isinstance(entry, x509.IPAddress)
    }

    assert dns_entries == {"localhost", "gateway", "edge.local"}
    assert ip_entries == {"127.0.0.1", "10.0.0.10"}

def test_build_san_invalid_ip_raises(monkeypatch):
    monkeypatch.setenv("BROKER_CERT_IPS", "999.1.1.1")

    with pytest.raises(ValueError, match="BROKER_CERT_IPS"):
        cu.build_san(
            default_dns=["localhost"],
            default_ips=["127.0.0.1"],
            dns_env="BROKER_CERT_DNS",
            ips_env="BROKER_CERT_IPS",
        )

def test_load_ca_roundtrip(certs_dir):
    ca_private_key = ec.generate_private_key(ec.SECP256R1())
    subject = cu.build_subject("UnitTest-CA")
    ca_cert = cu.build_root_ca_certificate(ca_private_key, subject)

    cu.write_keypair(str(certs_dir), "ca", ca_private_key, ca_cert)

    loaded_key, loaded_cert = cu.load_ca(str(certs_dir))

    assert loaded_cert.subject == subject
    assert loaded_cert.issuer == subject
    assert loaded_key.private_numbers() == ca_private_key.private_numbers()


def test_load_ca_missing_files_raises(certs_dir):
    with pytest.raises(FileNotFoundError, match="CA files not found"):
        cu.load_ca(str(certs_dir))
