import os
import sqlite3
import datetime
import logging
from contextlib import closing
from typing import Any, Dict, Tuple
from flask import Flask, request, jsonify, Response
from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Provisioner")

app = Flask(__name__)

# --- PROMETHEUS METRICS ---
PROV_ENROLL_REQUESTS = Counter(
    "prov_enrollment_requests_total",
    "Total enrollment requests received",
)
PROV_ENROLL_RESULTS = Counter(
    "prov_enrollment_results_total",
    "Enrollment results",
    ["result", "reason"],
)

# --- CONFIGURATION ---
# Paths are container-oriented by default, but can be overridden from environment
# to support local execution and tests.
CERTS_PATH = os.getenv("CERTS_PATH", "/app/certs")
DB_PATH = os.getenv("DB_PATH", "/app/data/gateway.db")
PROVISIONER_HOST = os.getenv("PROVISIONER_HOST", "0.0.0.0")
PROVISIONER_PORT = int(os.getenv("PROVISIONER_PORT", "5000"))
CLOCK_SKEW_SECONDS = int(os.getenv("CERT_CLOCK_SKEW_SECONDS", "7200"))

MIN_RSA_KEY_BITS = int(os.getenv("MIN_RSA_KEY_BITS", "2048"))
MIN_EC_KEY_BITS = int(os.getenv("MIN_EC_KEY_BITS", "256"))
DEFAULT_PEAK_POWER_WATTS = float(os.getenv("DEFAULT_PEAK_POWER_WATTS", "3000.0"))

CA_CERT_PATH = os.path.join(CERTS_PATH, "ca.crt")
CA_KEY_PATH = os.path.join(CERTS_PATH, "ca.key")

class InputValidationError(ValueError):
    """Raised when an enrollment request payload is malformed or incomplete."""


def _error_response(message: str, status_code: int):
    return jsonify({"error": message}), status_code

@app.route('/metrics', methods=['GET'])
def metrics():
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

def _parse_enroll_payload(req) -> Tuple[str, str, float, str]:
    """Validate request content type and extract enrollment data from JSON body."""
    if not req.is_json:
        raise InputValidationError("Content-Type must be application/json")
    
    data: Dict[str, Any] | None = req.get_json(silent=True)
    if not isinstance(data, dict):
        raise InputValidationError("Invalid JSON payload")
        
    device_id = data.get("device_id")
    csr_pem = data.get("csr")
    peak_power = data.get("peak_power")
    bootstrap_token = data.get("bootstrap_token")

    if not isinstance(device_id, str) or not device_id.strip():
        raise InputValidationError("Missing or invalid device_id")
    if len(device_id.strip()) > 128:
        raise InputValidationError("device_id is too long (max 128 chars)")
        
    if not isinstance(csr_pem, str) or not csr_pem.strip():
        raise InputValidationError("Missing or invalid csr")
    csr_pem = csr_pem.strip()
    if "BEGIN CERTIFICATE REQUEST" not in csr_pem:
        raise InputValidationError("csr must be a PEM-encoded certificate request")
        
    if isinstance(peak_power, bool) or not isinstance(peak_power, (int, float)):
        raise InputValidationError("Missing or invalid peak_power")
    peak_power = float(peak_power)
    if peak_power <= 0:
        raise InputValidationError("peak_power must be greater than 0")

    if not isinstance(bootstrap_token, str) or not bootstrap_token.strip():
        raise InputValidationError("Missing or invalid bootstrap_token")

    return device_id.strip(), csr_pem, peak_power, bootstrap_token.strip()

def _validate_csr_policy(csr: x509.CertificateSigningRequest, device_id: str) -> None:
    """Validate CSR against enrollment policy constraints."""
    # Policy 1: CSR subject CN must match the device identifier from the request.
    cn_attributes = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(cn_attributes) != 1:
        raise InputValidationError("CSR must contain exactly one Common Name (CN)")

    csr_cn = cn_attributes[0].value.strip()
    if csr_cn != device_id:
        raise InputValidationError("CSR Common Name (CN) must match device_id")

    # Policy 2: only RSA and EC keys are accepted.
    public_key = csr.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        # Policy 3a: enforce minimum RSA key size.
        if public_key.key_size < MIN_RSA_KEY_BITS:
            raise InputValidationError(
                f"RSA key too small: minimum {MIN_RSA_KEY_BITS} bits required"
            )
        return

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        # Policy 3b: enforce minimum EC key size (curve strength threshold).
        if public_key.key_size < MIN_EC_KEY_BITS:
            raise InputValidationError(
                f"EC key too small: minimum {MIN_EC_KEY_BITS} bits required"
            )
        return

    raise InputValidationError("Unsupported key algorithm in CSR (allowed: RSA, EC)")

def _load_csr(csr_pem: str, device_id: str) -> x509.CertificateSigningRequest:
    """Parse CSR and enforce enrollment policy checks."""
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode(), default_backend())
    except ValueError as exc:
        raise InputValidationError("Invalid CSR format") from exc

    _validate_csr_policy(csr, device_id)
    return csr

def _build_device_certificate(ca_cert: x509.Certificate, ca_key, csr: x509.CertificateSigningRequest, device_id: str):
    """Apply signing policy and generate a device leaf certificate."""
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    valid_from = now_utc - datetime.timedelta(seconds=max(CLOCK_SKEW_SECONDS, 0))
    valid_to = now_utc + datetime.timedelta(days=365)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, device_id),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Smart MicroGrid Trusted Domain"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"IT"),
    ]))

    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.public_key(csr.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(valid_from)
    builder = builder.not_valid_after(valid_to)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )

    return builder.sign(private_key=ca_key, algorithm=hashes.SHA256(), backend=default_backend())

def _store_device_public_key(device_id: str, public_key_pem: str, peak_power: float, token: str) -> None:
    """Insert or update device material atomically, burning the bootstrap token."""
    with closing(sqlite3.connect(DB_PATH)) as conn:
        cursor = conn.cursor()
        
        # 1. Verifica del Token
        cursor.execute("SELECT used, node_id FROM bootstrap_tokens WHERE token = ?", (token,))
        row = cursor.fetchone()
        
        if not row:
            raise InputValidationError("Invalid bootstrap token")
            
        used, assigned_node_id = row
        if used == 1:
            raise InputValidationError("Bootstrap token has already been used")
        if assigned_node_id and assigned_node_id != device_id:
            raise InputValidationError("Bootstrap token is assigned to a different device")
            
        # 2. Brucia il token associandolo definitivamente al dispositivo
        cursor.execute("UPDATE bootstrap_tokens SET used = 1, node_id = ? WHERE token = ?", (device_id, token))

        # 3. Salva la chiave pubblica del dispositivo
        cursor.execute('''
            INSERT INTO devices (node_id, public_key, trust_score, status, peak_power)
            VALUES (?, ?, 100, 0, ?)
            ON CONFLICT(node_id) DO UPDATE SET
                public_key=excluded.public_key,
                trust_score=100,
                status=0,
                peak_power=excluded.peak_power
        ''', (device_id, public_key_pem, peak_power))
        
        conn.commit()

def init_database():
    try:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        with closing(sqlite3.connect(DB_PATH)) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    node_id TEXT PRIMARY KEY,
                    public_key TEXT NOT NULL,
                    trust_score REAL DEFAULT 100.0,
                    status INTEGER DEFAULT 0,
                    last_seen TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    peak_power REAL DEFAULT 3000.0
                )
            ''')
            # --- TABELLA TOKEN ---
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS bootstrap_tokens (
                    token TEXT PRIMARY KEY,
                    node_id TEXT,
                    used INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            # Generazione automatica di token di test per la tesi
            cursor.execute("INSERT OR IGNORE INTO bootstrap_tokens (token, node_id) VALUES ('token-ESP', 'SmartMeter_ESP')")
            cursor.execute("INSERT OR IGNORE INTO bootstrap_tokens (token, node_id) VALUES ('token-001', 'SmartMeter_001')")
            
            try:
                cursor.execute(f"ALTER TABLE devices ADD COLUMN peak_power REAL DEFAULT {DEFAULT_PEAK_POWER_WATTS}")
            except sqlite3.OperationalError:
                pass
            cursor.execute("UPDATE devices SET peak_power = COALESCE(peak_power, ?)", (DEFAULT_PEAK_POWER_WATTS,))
            conn.commit()
        logger.info(f"[PROVISION] Database initialized at {DB_PATH}")
    except Exception as e:
        logger.error(f"[PROVISION] Failed to initialize database: {e}")

def get_ca_credentials():
    '''
    Load CA certificate and private key used to sign device certificates.

    Returns:
        tuple(ca_cert, ca_key) on success, (None, None) on failure.

    Any failure is logged and intentionally converted to a safe fallback so
    request handlers can return controlled HTTP 500 responses.
    '''
    try:
        with open(CA_CERT_PATH, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        with open(CA_KEY_PATH, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
            
        return ca_cert, ca_key
    except Exception as e:
        logger.error(f"[PROVISION] Error loading CA: {e}")
        return None, None

@app.route('/enroll', methods=['POST'])
def enroll():
    PROV_ENROLL_REQUESTS.inc()
    try:
        # ---> RIGA CORRETTA: Ora spacchettiamo 4 valori <---
        device_id, csr_pem, peak_power, bootstrap_token = _parse_enroll_payload(request)
        
        ca_cert, ca_key = get_ca_credentials()
        if not ca_cert or not ca_key:
            PROV_ENROLL_RESULTS.labels(result="rejected", reason="ca_unavailable").inc()
            return _error_response("Internal Server Error: CA not available", 500)
            
        csr = _load_csr(csr_pem, device_id)
        certificate = _build_device_certificate(ca_cert, ca_key, csr, device_id)
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
        
        public_key_pem = csr.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        # Passiamo il token alla funzione del database
        _store_device_public_key(device_id, public_key_pem, peak_power, bootstrap_token)
        
        logger.info(f"[PROVISION] Device {device_id} enrolled successfully")
        PROV_ENROLL_RESULTS.labels(result="accepted", reason="ok").inc()
        
        return jsonify({
            "status": "success",
            "certificate": cert_pem,
            "ca_certificate": ca_cert.public_bytes(serialization.Encoding.PEM).decode()
        })
    except InputValidationError as e:
        PROV_ENROLL_RESULTS.labels(result="rejected", reason="validation_error").inc()
        return _error_response(str(e), 400)
    except Exception as e:
        logger.error(f"[PROVISION] Enrollment failed: {str(e)}")
        PROV_ENROLL_RESULTS.labels(result="rejected", reason="internal_error").inc()
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Initialize local state before serving requests.
    init_database()

    logger.info(
        f"[PROVISION] Starting HTTP enrollment backend on {PROVISIONER_HOST}:{PROVISIONER_PORT}"
    )
    app.run(
        host=PROVISIONER_HOST,
        port=PROVISIONER_PORT,
    )