import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID
from flask import request

import provisioner

def _create_self_signed_ca(common_name: str = "Test-Root-CA"):
    ca_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Trusted-MicroGrid"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
        ]
    )

    now_utc = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now_utc - timedelta(hours=1))
        .not_valid_after(now_utc + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return ca_key, cert

def _build_csr(device_id: str, key_type: str = "ec", rsa_bits: int = 2048):
    if key_type == "ec":
        private_key = ec.generate_private_key(ec.SECP256R1())
        algorithm = hashes.SHA256()
    elif key_type == "rsa":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
        algorithm = hashes.SHA256()
    elif key_type == "ed25519":
        private_key = ed25519.Ed25519PrivateKey.generate()
        algorithm = None
    else:
        raise ValueError("Unsupported test key type")

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, device_id),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Trusted-MicroGrid"),
                ]
            )
        )
        .sign(private_key, algorithm)
    )

    return private_key, csr

@pytest.fixture
def provisioner_paths(tmp_path, monkeypatch):
    certs_path = tmp_path / "certs"
    certs_path.mkdir(parents=True, exist_ok=True)

    db_path = tmp_path / "gateway.db"
    ca_key_path = certs_path / "ca.key"
    ca_cert_path = certs_path / "ca.crt"

    monkeypatch.setattr(provisioner, "DB_PATH", str(db_path))
    monkeypatch.setattr(provisioner, "CA_KEY_PATH", str(ca_key_path))
    monkeypatch.setattr(provisioner, "CA_CERT_PATH", str(ca_cert_path))

    return {
        "db_path": db_path,
        "ca_key_path": ca_key_path,
        "ca_cert_path": ca_cert_path,
        "certs_path": certs_path,
    }

@pytest.fixture
def flask_client():
    return provisioner.app.test_client()

def _write_ca_material(ca_key_path, ca_cert_path):
    ca_key, ca_cert = _create_self_signed_ca()

    ca_key_path.write_bytes(
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    return ca_key, ca_cert


def test_init_database_creates_devices_table(provisioner_paths):
    provisioner.init_database()

    with closing(sqlite3.connect(provisioner.DB_PATH)) as conn:
        columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(devices)").fetchall()
        }

    assert {
        "node_id",
        "public_key",
        "trust_score",
        "status",
        "last_seen",
        "created_at",
        "peak_power",
    }.issubset(columns)

def test_store_device_public_key_upsert(provisioner_paths):
    provisioner.init_database()

    provisioner._store_device_public_key("node-1", "PUBKEY-A", 2500.0)
    provisioner._store_device_public_key("node-1", "PUBKEY-B", 3200.0)

    with closing(sqlite3.connect(provisioner.DB_PATH)) as conn:
        row = conn.execute(
            "SELECT public_key, trust_score, status, peak_power FROM devices WHERE node_id = ?",
            ("node-1",),
        ).fetchone()

    assert row == ("PUBKEY-B", 100.0, 0, 3200.0)

def test_parse_enroll_payload_rejects_non_json_request():
    with provisioner.app.test_request_context(
        "/enroll", method="POST", data="plain-text", content_type="text/plain"
    ):
        with pytest.raises(provisioner.InputValidationError, match="Content-Type"):
            provisioner._parse_enroll_payload(request)

def test_parse_enroll_payload_accepts_valid_json():
    with provisioner.app.test_request_context(
        "/enroll",
        method="POST",
        json={
            "device_id": "device-1",
            "csr": "-----BEGIN CERTIFICATE REQUEST-----\nABC\n-----END CERTIFICATE REQUEST-----",
            "peak_power": 3300,
        },
    ):
        device_id, csr_pem, peak_power = provisioner._parse_enroll_payload(request)

    assert device_id == "device-1"
    assert "BEGIN CERTIFICATE REQUEST" in csr_pem
    assert peak_power == 3300.0

@pytest.mark.parametrize(
    "payload, error_pattern",
    [
        ({"csr": "-----BEGIN CERTIFICATE REQUEST-----X", "peak_power": 3000}, "device_id"),
        ({"device_id": "x" * 129, "csr": "-----BEGIN CERTIFICATE REQUEST-----X", "peak_power": 3000}, "too long"),
        ({"device_id": "device-1", "csr": "not-a-pem", "peak_power": 3000}, "PEM-encoded"),
        ({"device_id": "device-1", "csr": "", "peak_power": 3000}, "invalid csr"),
        ({"device_id": "device-1", "csr": "-----BEGIN CERTIFICATE REQUEST-----X"}, "peak_power"),
        ({"device_id": "device-1", "csr": "-----BEGIN CERTIFICATE REQUEST-----X", "peak_power": "3kW"}, "peak_power"),
        ({"device_id": "device-1", "csr": "-----BEGIN CERTIFICATE REQUEST-----X", "peak_power": 0}, "greater than 0"),
    ],
)
def test_parse_enroll_payload_validation_errors(payload, error_pattern):
    with provisioner.app.test_request_context("/enroll", method="POST", json=payload):
        with pytest.raises(provisioner.InputValidationError, match=error_pattern):
            provisioner._parse_enroll_payload(request)

def test_validate_csr_policy_rejects_cn_mismatch():
    _, csr = _build_csr("device-other", key_type="ec")

    with pytest.raises(provisioner.InputValidationError, match="must match device_id"):
        provisioner._validate_csr_policy(csr, "device-1")

def test_validate_csr_policy_rejects_small_rsa(monkeypatch):
    monkeypatch.setattr(provisioner, "MIN_RSA_KEY_BITS", 2048)
    _, csr = _build_csr("device-1", key_type="rsa", rsa_bits=1024)

    with pytest.raises(provisioner.InputValidationError, match="RSA key too small"):
        provisioner._validate_csr_policy(csr, "device-1")

def test_validate_csr_policy_rejects_unsupported_algorithm():
    _, csr = _build_csr("device-1", key_type="ed25519")

    with pytest.raises(provisioner.InputValidationError, match="Unsupported key algorithm"):
        provisioner._validate_csr_policy(csr, "device-1")

def test_load_csr_rejects_invalid_pem():
    with pytest.raises(provisioner.InputValidationError, match="Invalid CSR format"):
        provisioner._load_csr("-----BEGIN CERTIFICATE REQUEST-----BAD", "device-1")

def test_build_device_certificate_sets_subject_and_ca_false():
    ca_key, ca_cert = _create_self_signed_ca()
    _, csr = _build_csr("device-1", key_type="ec")

    cert = provisioner._build_device_certificate(ca_cert, ca_key, csr, "device-1")

    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value

    assert cn == "device-1"
    assert cert.issuer == ca_cert.subject
    assert bc.ca is False

def test_enroll_success_returns_cert_and_persists_device(provisioner_paths, flask_client):
    _, ca_cert = _write_ca_material(provisioner_paths["ca_key_path"], provisioner_paths["ca_cert_path"])
    provisioner.init_database()

    _, csr = _build_csr("device-123", key_type="ec")
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

    resp = flask_client.post(
        "/enroll",
        json={"device_id": "device-123", "csr": csr_pem, "peak_power": 4200},
    )

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "success"
    assert "BEGIN CERTIFICATE" in body["certificate"]
    assert ca_cert.public_bytes(serialization.Encoding.PEM).decode().strip() == body["ca_certificate"].strip()

    with closing(sqlite3.connect(provisioner.DB_PATH)) as conn:
        row = conn.execute(
            "SELECT node_id, public_key, trust_score, status, peak_power FROM devices WHERE node_id = ?",
            ("device-123",),
        ).fetchone()

    assert row is not None
    assert row[0] == "device-123"
    assert "BEGIN PUBLIC KEY" in row[1]
    assert row[2] == 100.0
    assert row[3] == 0
    assert row[4] == 4200.0

def test_enroll_returns_400_for_invalid_json_payload(flask_client):
    resp = flask_client.post(
        "/enroll",
        data="not-json",
        content_type="application/json",
    )

    assert resp.status_code == 400
    assert "error" in resp.get_json()

def test_enroll_returns_500_when_ca_unavailable(monkeypatch, flask_client):
    monkeypatch.setattr(provisioner, "get_ca_credentials", lambda: (None, None))

    resp = flask_client.post(
        "/enroll",
        json={
            "device_id": "device-1",
            "csr": "-----BEGIN CERTIFICATE REQUEST-----\nX\n-----END CERTIFICATE REQUEST-----",
            "peak_power": 3000,
        },
    )

    assert resp.status_code == 500
    assert resp.get_json()["error"] == "Internal Server Error: CA not available"