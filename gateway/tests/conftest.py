from pathlib import Path
import sys

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CA_DIR = PROJECT_ROOT / "src" / "ca"
PROVISIONING_DIR = PROJECT_ROOT / "src" / "provisioning"
TRUST_ENGINE_DIR = PROJECT_ROOT / "src" / "trust_engine"

if str(CA_DIR) not in sys.path:
    sys.path.insert(0, str(CA_DIR))

if str(PROVISIONING_DIR) not in sys.path:
    sys.path.insert(0, str(PROVISIONING_DIR))

if str(TRUST_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(TRUST_ENGINE_DIR))


@pytest.fixture(autouse=True)
def clean_cert_env(monkeypatch):
    for var_name in [
        "CERTS_PATH",
        "CERT_CLOCK_SKEW_SECONDS",
        "CERT_VALIDITY_DAYS",
        "BROKER_CERT_DNS",
        "BROKER_CERT_IPS",
        "PROVISIONER_CERT_DNS",
        "PROVISIONER_CERT_IPS",
        "NODERED_CERT_CN",
    ]:
        monkeypatch.delenv(var_name, raising=False)


@pytest.fixture
def certs_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("CERTS_PATH", str(tmp_path))
    return tmp_path