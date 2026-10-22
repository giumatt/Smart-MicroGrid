import importlib
import json
import sqlite3
import sys
import time
import types
from contextlib import closing

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from prometheus_client import REGISTRY


# --- FAKE CLASSES FOR WEB3 AND MQTT ---
class _FakeMqttClient:
    def __init__(self):
        self.published = []

    def publish(self, topic, payload, qos=0):
        self.published.append((topic, json.loads(payload)))


class _Msg:
    def __init__(self, payload_dict):
        self.payload = json.dumps(payload_dict).encode()


@pytest.fixture
def relayer(monkeypatch, tmp_path):
    fake_web3 = types.ModuleType("web3")
    fake_web3.Web3 = object
    monkeypatch.setitem(sys.modules, "web3", fake_web3)
    monkeypatch.setitem(sys.modules, "solcx", types.ModuleType("solcx"))

    # Empties the Prometheus global registry to avoid conflicts between tests
    for collector in list(REGISTRY._collector_to_names.keys()):
        REGISTRY.unregister(collector)

    if "blockchain" in sys.modules:
        del sys.modules["blockchain"]
    module = importlib.import_module("blockchain")

    db_path = tmp_path / "gateway.db"
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute("CREATE TABLE devices (node_id TEXT PRIMARY KEY, public_key TEXT, status INTEGER)")
        conn.commit()
    monkeypatch.setattr(module, "DB_PATH", str(db_path))

    recorded = []

    def _fake_record(from_node, to_node, wh_amount, timestamp, seq, signature):
        recorded.append((from_node, wh_amount, seq))
        return "0xabc", len(recorded)

    monkeypatch.setattr(module, "record_transfer_on_chain", _fake_record)
    module.recorded = recorded
    return module


def _register(module, node_id, status=0):
    private_key = ec.generate_private_key(ec.SECP256R1())
    pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    with closing(sqlite3.connect(module.DB_PATH)) as conn:
        conn.execute("INSERT INTO devices VALUES (?, ?, ?)", (node_id, pem, status))
        conn.commit()
    return private_key


def _envelope(private_key, node_id="node-1", seq=1, production="1440.00", interval_s=10.0, timestamp=None):
    timestamp = int(time.time()) if timestamp is None else timestamp
    signed = f'{{"node_id":"{node_id}","timestamp":{timestamp},"seq":{seq},"production":{production}}}'
    power = float(production)
    return {
        "from_node": node_id,
        "to_node": "grid",
        "seq": seq,
        "power_w": power,
        "interval_s": interval_s,
        "wh_amount": power * interval_s / 3600.0,
        "timestamp": timestamp,
        "sig": private_key.sign(signed.encode(), ec.ECDSA(hashes.SHA256())).hex(),
        "signed_payload": signed,
    }


def test_valid_transfer_is_recorded_and_announced(relayer):
    key = _register(relayer, "node-1")
    client = _FakeMqttClient()

    relayer.on_message(client, None, _Msg(_envelope(key)))

    assert relayer.recorded == [("node-1", pytest.approx(4.0), 1)]
    assert client.published[0][0] == relayer.MQTT_OUT_TOPIC


def test_replayed_transfer_is_rejected(relayer):
    key = _register(relayer, "node-1")
    envelope = _envelope(key)

    relayer.on_message(_FakeMqttClient(), None, _Msg(envelope))
    relayer.on_message(_FakeMqttClient(), None, _Msg(envelope))

    assert len(relayer.recorded) == 1


def test_zero_energy_fields_are_not_treated_as_missing(relayer):
    key = _register(relayer, "node-1")
    envelope = _envelope(key, production="0.00", interval_s=0.0)

    transfer, reason = relayer.validate_transfer(envelope)

    assert reason is None
    assert transfer["wh_amount"] == 0.0


def test_inflated_energy_is_rejected(relayer):
    key = _register(relayer, "node-1")
    envelope = _envelope(key)
    envelope["wh_amount"] = 1440.0  # power credited as energy

    assert relayer.validate_transfer(envelope) == (None, "energy_mismatch")


def test_interval_above_cap_is_rejected(relayer):
    key = _register(relayer, "node-1")
    envelope = _envelope(key, interval_s=relayer.MAX_ENERGY_INTERVAL_S + 1)

    assert relayer.validate_transfer(envelope) == (None, "energy_mismatch")


def test_power_not_matching_signed_production_is_rejected(relayer):
    key = _register(relayer, "node-1")
    envelope = _envelope(key)
    envelope["power_w"] = 5000.0
    envelope["wh_amount"] = 5000.0 * 10 / 3600

    assert relayer.validate_transfer(envelope) == (None, "amount_mismatch")


def test_stale_transfer_is_rejected(relayer):
    key = _register(relayer, "node-1")
    envelope = _envelope(key, timestamp=int(time.time()) - 3600)

    assert relayer.validate_transfer(envelope) == (None, "stale_transfer")


def test_tampered_signed_payload_fails_signature(relayer):
    key = _register(relayer, "node-1")
    envelope = _envelope(key)
    envelope["signed_payload"] = envelope["signed_payload"].replace("1440.00", "1440.0")

    relayer.on_message(_FakeMqttClient(), None, _Msg(envelope))

    assert relayer.recorded == []


def test_banned_node_is_rejected(relayer):
    key = _register(relayer, "node-1", status=1)

    relayer.on_message(_FakeMqttClient(), None, _Msg(_envelope(key)))

    assert relayer.recorded == []
