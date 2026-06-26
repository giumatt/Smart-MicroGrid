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

class _FakeWriteAPI:
    def __init__(self):
        self.calls = []

    def write(self, **kwargs):
        self.calls.append(kwargs)

class _FakeInfluxClient:
    def __init__(self, *args, **kwargs):
        self._write_api = _FakeWriteAPI()

    def write_api(self, write_options=None):
        return self._write_api

class _FakePoint:
    def __init__(self, measurement):
        self.measurement = measurement
        self.tags = {}
        self.fields = {}
        self.ts = None

    def tag(self, key, value):
        self.tags[key] = value
        return self

    def field(self, key, value):
        self.fields[key] = value
        return self

    def time(self, ts):
        self.ts = ts
        return self

class _DummyMsg:
    def __init__(self, payload_dict):
        self.payload = json.dumps(payload_dict).encode()

class _RawMsg:
    def __init__(self, payload_bytes):
        self.payload = payload_bytes

class _FakeResponse:
    def __init__(self, radiation):
        self._radiation = radiation

    def raise_for_status(self):
        return None

    def json(self):
        return {"current": {"shortwave_radiation": self._radiation}}

class _FakeMqttClient:
    def __init__(self):
        self.subscribed_topics = []

    def subscribe(self, topic):
        self.subscribed_topics.append(topic)

class _ReasonCode:
    def __init__(self, value=None, rc=None, is_failure=None):
        self.value = value
        self.rc = rc
        self.is_failure = is_failure

class _FakeTlsClient:
    def __init__(self):
        self.tls_args = None

    def tls_set(self, **kwargs):
        self.tls_args = kwargs

def _install_fake_influx(monkeypatch):
    fake_influxdb_client = types.ModuleType("influxdb_client")
    fake_influxdb_client.InfluxDBClient = _FakeInfluxClient
    fake_influxdb_client.Point = _FakePoint

    fake_influxdb_client_client = types.ModuleType("influxdb_client.client")
    fake_influxdb_client_write_api = types.ModuleType("influxdb_client.client.write_api")
    fake_influxdb_client_write_api.SYNCHRONOUS = object()

    monkeypatch.setitem(sys.modules, "influxdb_client", fake_influxdb_client)
    monkeypatch.setitem(sys.modules, "influxdb_client.client", fake_influxdb_client_client)
    monkeypatch.setitem(sys.modules, "influxdb_client.client.write_api", fake_influxdb_client_write_api)

@pytest.fixture
def trust_engine_module(monkeypatch, tmp_path):
    _install_fake_influx(monkeypatch)

    if "trust_engine" in sys.modules:
        del sys.modules["trust_engine"]

    module = importlib.import_module("trust_engine")
    monkeypatch.setattr(module, "DB_PATH", str(tmp_path / "gateway.db"))
    module.init_db()
    return module

def _insert_device(module, node_id, public_key="PUB", trust_score=100.0, status=0, peak_power=3000.0):
    with closing(sqlite3.connect(module.DB_PATH)) as conn:
        conn.execute(
            """
            INSERT INTO devices (node_id, public_key, trust_score, status, peak_power)
            VALUES (?, ?, ?, ?, ?)
            """,
            (node_id, public_key, trust_score, status, peak_power),
        )
        conn.commit()

def _create_signed_payload(private_key, node_id, timestamp, production):
    payload = {
        "node_id": node_id,
        "timestamp": int(timestamp),
        "production": float(production),
    }
    payload_str = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
    signature = private_key.sign(payload_str.encode("utf-8"), ec.ECDSA(hashes.SHA256())).hex()
    payload["sig"] = signature
    return payload

def test_init_db_creates_canonical_schema(trust_engine_module):
    with closing(sqlite3.connect(trust_engine_module.DB_PATH)) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(devices)").fetchall()}

    assert {"node_id", "public_key", "trust_score", "status", "last_seen", "created_at", "peak_power"}.issubset(columns)

def test_check_device_status_and_ban(trust_engine_module):
    _insert_device(trust_engine_module, "node-ok", trust_score=88.0, status=0, peak_power=3500.0)
    _insert_device(trust_engine_module, "node-bad", status=1)

    with closing(sqlite3.connect(trust_engine_module.DB_PATH)) as conn:
        cursor = conn.cursor()
        assert trust_engine_module.check_device_status(cursor, "missing") == (None, None, None)
        assert trust_engine_module.check_device_status(cursor, "node-ok") == (0, 88.0, 3500.0)
        assert trust_engine_module.check_device_status(cursor, "node-bad") == (1, 100.0, 3000.0)

        trust_engine_module.ban_device(cursor, "node-ok")
        conn.commit()

        new_status = conn.execute(
            "SELECT status FROM devices WHERE node_id = ?",
            ("node-ok",),
        ).fetchone()[0]

    assert new_status == 1

def test_verify_integrity_success_and_failure(trust_engine_module):
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    _insert_device(trust_engine_module, "node-1", public_key=public_key_pem)

    data = {"node_id": "node-1", "timestamp": 123, "production": 12.5}
    payload_str = json.dumps(data, separators=(",", ":"))
    valid_signature = private_key.sign(payload_str.encode(), ec.ECDSA(hashes.SHA256())).hex()

    assert trust_engine_module.verify_integrity(data, valid_signature, "node-1") is True
    assert trust_engine_module.verify_integrity(data, "deadbeef", "node-1") is False
    assert trust_engine_module.verify_integrity(data, valid_signature, "missing-node") is False

def test_get_fallback_yield_night_and_day(trust_engine_module, monkeypatch):
    monkeypatch.setattr(
        trust_engine_module.time,
        "localtime",
        lambda _: time.struct_time((2026, 4, 22, 2, 0, 0, 0, 0, -1)),
    )
    assert trust_engine_module.get_fallback_yield() == 0.0

    monkeypatch.setattr(
        trust_engine_module.time,
        "localtime",
        lambda _: time.struct_time((2026, 4, 22, 12, 0, 0, 0, 0, -1)),
    )
    assert trust_engine_module.get_fallback_yield() > 0.0

def test_get_current_forecast_updates_cache_on_api_success(trust_engine_module, monkeypatch):
    trust_engine_module.forecast_cache = {"timestamp": 0, "yield_percentage": 0.0}
    monkeypatch.setattr(trust_engine_module.time, "time", lambda: 2000.0)
    monkeypatch.setattr(trust_engine_module.requests, "get", lambda url, timeout: _FakeResponse(500.0))

    value = trust_engine_module.get_current_forecast()

    assert value == pytest.approx(0.5)
    assert trust_engine_module.forecast_cache["yield_percentage"] == pytest.approx(0.5)
    assert trust_engine_module.forecast_cache["timestamp"] == 2000.0

def test_get_current_forecast_uses_cache_without_new_http_call(trust_engine_module, monkeypatch):
    trust_engine_module.forecast_cache = {"timestamp": 1900.0, "yield_percentage": 0.77}
    monkeypatch.setattr(trust_engine_module.time, "time", lambda: 2000.0)

    def _unexpected_call(url, timeout):
        raise AssertionError("requests.get should not be called when cache is fresh")

    monkeypatch.setattr(trust_engine_module.requests, "get", _unexpected_call)

    assert trust_engine_module.get_current_forecast() == pytest.approx(0.77)

def test_get_current_forecast_uses_fallback_on_api_error(trust_engine_module, monkeypatch):
    trust_engine_module.forecast_cache = {"timestamp": 0, "yield_percentage": 0.0}
    monkeypatch.setattr(trust_engine_module.time, "time", lambda: 2000.0)
    monkeypatch.setattr(
        trust_engine_module.requests,
        "get",
        lambda url, timeout: (_ for _ in ()).throw(RuntimeError("network error")),
    )
    monkeypatch.setattr(trust_engine_module, "get_fallback_yield", lambda: 0.33)

    value = trust_engine_module.get_current_forecast()

    assert value == pytest.approx(0.33)
    assert trust_engine_module.forecast_cache["yield_percentage"] == pytest.approx(0.33)
    assert trust_engine_module.forecast_cache["timestamp"] == 2000.0

def test_on_message_rejects_incomplete_payload(trust_engine_module):
    msg = _DummyMsg({"node_id": "node-1", "timestamp": int(time.time())})
    trust_engine_module.on_message(None, None, msg)
    assert trust_engine_module.write_api.calls == []

def test_on_message_blocks_invalid_signature(trust_engine_module):
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    _insert_device(trust_engine_module, "node-1", public_key=public_key_pem)

    payload = {
        "node_id": "node-1",
        "timestamp": int(time.time()),
        "production": 1000.0,
        "sig": "00",
    }

    trust_engine_module.on_message(None, None, _DummyMsg(payload))

    with closing(sqlite3.connect(trust_engine_module.DB_PATH)) as conn:
        trust_score = conn.execute(
            "SELECT trust_score FROM devices WHERE node_id = ?",
            ("node-1",),
        ).fetchone()[0]

    assert trust_score == 100.0
    assert trust_engine_module.write_api.calls == []

def test_on_message_rejects_unregistered_device(trust_engine_module, monkeypatch):
    monkeypatch.setattr(trust_engine_module, "verify_integrity", lambda *args, **kwargs: True)
    msg = _DummyMsg({"node_id": "node-missing", "timestamp": int(time.time()), "production": 1.0, "sig": "00"})
    trust_engine_module.on_message(None, None, msg)
    assert trust_engine_module.write_api.calls == []

def test_on_message_rejects_banned_device(trust_engine_module):
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    _insert_device(trust_engine_module, "node-banned", public_key=public_key_pem, status=1)

    msg = _DummyMsg(_create_signed_payload(private_key, "node-banned", int(time.time()), 1.0))
    trust_engine_module.on_message(None, None, msg)
    assert trust_engine_module.write_api.calls == []

def test_on_message_temporal_anomaly_updates_trust_and_bans(trust_engine_module, monkeypatch):
    monkeypatch.setattr(trust_engine_module, "TIME_WINDOW", 10)
    monkeypatch.setattr(trust_engine_module, "TRUST_THRESHOLD_BAN", 20.0)

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    _insert_device(trust_engine_module, "node-1", public_key=public_key_pem, trust_score=25.0, status=0)

    old_ts = int(time.time()) - 999
    msg = _DummyMsg(_create_signed_payload(private_key, "node-1", old_ts, 1.0))
    trust_engine_module.on_message(None, None, msg)

    with closing(sqlite3.connect(trust_engine_module.DB_PATH)) as conn:
        trust_score, status = conn.execute(
            "SELECT trust_score, status FROM devices WHERE node_id = ?",
            ("node-1",),
        ).fetchone()

    assert trust_score == 10.0
    assert status == 1
    assert trust_engine_module.write_api.calls == []

def test_on_message_meteo_anomaly_applies_penalty(trust_engine_module, monkeypatch):
    monkeypatch.setattr(trust_engine_module, "TRUST_THRESHOLD_BAN", 20.0)
    monkeypatch.setattr(trust_engine_module, "get_current_forecast", lambda: 1.0)

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    _insert_device(trust_engine_module, "node-1", public_key=public_key_pem, trust_score=50.0, status=0, peak_power=3000.0)

    msg = _DummyMsg(_create_signed_payload(private_key, "node-1", int(time.time()), 1000.0))
    trust_engine_module.on_message(None, None, msg)

    with closing(sqlite3.connect(trust_engine_module.DB_PATH)) as conn:
        trust_score, status = conn.execute(
            "SELECT trust_score, status FROM devices WHERE node_id = ?",
            ("node-1",),
        ).fetchone()

    assert trust_score == 35.0
    assert status == 0
    assert len(trust_engine_module.write_api.calls) == 1

def test_on_message_self_healing_increases_trust_and_updates_last_seen(trust_engine_module, monkeypatch):
    monkeypatch.setattr(trust_engine_module, "get_current_forecast", lambda: 0.5)

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    _insert_device(trust_engine_module, "node-1", public_key=public_key_pem, trust_score=80.0, status=0, peak_power=3000.0)

    msg = _DummyMsg(_create_signed_payload(private_key, "node-1", int(time.time()), 1520.0))

    trust_engine_module.on_message(None, None, msg)

    assert len(trust_engine_module.write_api.calls) == 1
    call = trust_engine_module.write_api.calls[0]
    assert call["bucket"] == trust_engine_module.INFLUX_BUCKET

    with closing(sqlite3.connect(trust_engine_module.DB_PATH)) as conn:
        last_seen = conn.execute(
            "SELECT last_seen FROM devices WHERE node_id = ?",
            ("node-1",),
        ).fetchone()[0]

        trust_score = conn.execute(
            "SELECT trust_score FROM devices WHERE node_id = ?",
            ("node-1",),
        ).fetchone()[0]

    assert last_seen is not None
    assert trust_score == 82.0

def test_on_message_bans_and_skips_influx_write_when_trust_drops_below_threshold(trust_engine_module, monkeypatch):
    monkeypatch.setattr(trust_engine_module, "TRUST_THRESHOLD_BAN", 20.0)
    monkeypatch.setattr(trust_engine_module, "get_current_forecast", lambda: 1.0)

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    _insert_device(trust_engine_module, "node-1", public_key=public_key_pem, trust_score=30.0, status=0, peak_power=3000.0)

    msg = _DummyMsg(_create_signed_payload(private_key, "node-1", int(time.time()), 0.0))
    trust_engine_module.on_message(None, None, msg)

    with closing(sqlite3.connect(trust_engine_module.DB_PATH)) as conn:
        trust_score, status = conn.execute(
            "SELECT trust_score, status FROM devices WHERE node_id = ?",
            ("node-1",),
        ).fetchone()

    assert trust_score == 15.0
    assert status == 1
    assert trust_engine_module.write_api.calls == []

def test_on_connect_subscribes_when_connection_is_ok(trust_engine_module):
    fake_client = _FakeMqttClient()

    trust_engine_module.on_connect(fake_client, None, None, 0, None)

    assert fake_client.subscribed_topics == [trust_engine_module.MQTT_TOPIC]

def test_on_connect_does_not_subscribe_when_connection_fails(trust_engine_module):
    fake_client = _FakeMqttClient()

    trust_engine_module.on_connect(fake_client, None, None, 5, None)

    assert fake_client.subscribed_topics == []

def test_on_disconnect_accepts_both_success_and_error_codes(trust_engine_module):
    trust_engine_module.on_disconnect(None, None, None, 0, None)
    trust_engine_module.on_disconnect(None, None, None, 7, None)

def test_reason_code_to_int_accepts_multiple_shapes(trust_engine_module):
    assert trust_engine_module._reason_code_to_int(3) == 3
    assert trust_engine_module._reason_code_to_int(3.9) == 3
    assert trust_engine_module._reason_code_to_int(_ReasonCode(value=5)) == 5
    assert trust_engine_module._reason_code_to_int(_ReasonCode(rc=7)) == 7
    assert trust_engine_module._reason_code_to_int("8") == 8
    assert trust_engine_module._reason_code_to_int("bad") is None

def test_on_connect_respects_is_failure_flag(trust_engine_module):
    fake_client = _FakeMqttClient()
    trust_engine_module.on_connect(fake_client, None, None, _ReasonCode(rc=0, is_failure=True), None)
    assert fake_client.subscribed_topics == []

    trust_engine_module.on_connect(fake_client, None, None, _ReasonCode(rc=5, is_failure=False), None)
    assert fake_client.subscribed_topics == [trust_engine_module.MQTT_TOPIC]

def test_on_disconnect_respects_is_failure_flag(trust_engine_module):
    trust_engine_module.on_disconnect(None, None, None, _ReasonCode(rc=0, is_failure=True), None)
    trust_engine_module.on_disconnect(None, None, None, _ReasonCode(rc=7, is_failure=False), None)

def test_configure_mqtt_tls_disabled_skips_tls_setup(trust_engine_module, monkeypatch):
    fake_client = _FakeTlsClient()
    monkeypatch.setattr(trust_engine_module, "MQTT_USE_TLS", False)
    trust_engine_module._configure_mqtt_tls(fake_client)
    assert fake_client.tls_args is None

def test_configure_mqtt_tls_raises_when_files_missing(trust_engine_module, monkeypatch):
    monkeypatch.setattr(trust_engine_module, "MQTT_USE_TLS", True)
    monkeypatch.setattr(trust_engine_module, "MQTT_TLS_CA_CERT", "/missing/ca.crt")
    monkeypatch.setattr(trust_engine_module, "MQTT_TLS_CERT", "/missing/client.crt")
    monkeypatch.setattr(trust_engine_module, "MQTT_TLS_KEY", "/missing/client.key")
    monkeypatch.setattr(trust_engine_module.os.path, "isfile", lambda _: False)

    with pytest.raises(FileNotFoundError):
        trust_engine_module._configure_mqtt_tls(_FakeTlsClient())

def test_configure_mqtt_tls_sets_client_when_files_present(trust_engine_module, monkeypatch):
    monkeypatch.setattr(trust_engine_module, "MQTT_USE_TLS", True)
    monkeypatch.setattr(trust_engine_module, "MQTT_TLS_CA_CERT", "/certs/ca.crt")
    monkeypatch.setattr(trust_engine_module, "MQTT_TLS_CERT", "/certs/client.crt")
    monkeypatch.setattr(trust_engine_module, "MQTT_TLS_KEY", "/certs/client.key")
    monkeypatch.setattr(trust_engine_module.os.path, "isfile", lambda _: True)

    fake_client = _FakeTlsClient()
    trust_engine_module._configure_mqtt_tls(fake_client)

    assert fake_client.tls_args == {
        "ca_certs": "/certs/ca.crt",
        "certfile": "/certs/client.crt",
        "keyfile": "/certs/client.key",
    }

def test_on_message_handles_invalid_json(trust_engine_module):
    trust_engine_module.on_message(None, None, _RawMsg(b"not-json"))
    assert trust_engine_module.write_api.calls == []

def test_on_message_handles_value_error(trust_engine_module):
    msg = _DummyMsg({"node_id": "node-1", "timestamp": int(time.time()), "production": "abc", "sig": "00"})
    trust_engine_module.on_message(None, None, msg)
    assert trust_engine_module.write_api.calls == []