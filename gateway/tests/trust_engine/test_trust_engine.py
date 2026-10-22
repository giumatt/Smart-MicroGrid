import calendar
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

# --- FAKE CLASSES FOR INFLUXDB ---
class _FakeWriteAPI:
    def __init__(self):
        self.calls = []

    def write(self, **kwargs):
        self.calls.append(kwargs)

class _FakeRecord:
    """Mirrors influxdb_client FluxRecord: the yield() name lives in the "result" column."""
    def __init__(self, result, value, node_id=None):
        self.values = {"result": result, "_measurement": "production", "_value": value}
        if node_id is not None:
            self.values["node_id"] = node_id

    def get_value(self):
        return self.values["_value"]

class _FakeTable:
    def __init__(self, records):
        self.records = records

class _FakeQueryAPI:
    def __init__(self):
        self.query_result = []

    def query(self, q):
        return self.query_result

class _FakeInfluxClient:
    def __init__(self, *args, **kwargs):
        self._write_api = _FakeWriteAPI()
        self._query_api = _FakeQueryAPI()

    def write_api(self, write_options=None):
        return self._write_api

    def query_api(self):
        return self._query_api

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

# --- FAKE CLASSES FOR MQTT AND HTTP ---
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
        self.published = []

    def subscribe(self, topic):
        self.subscribed_topics.append(topic)

    def publish(self, topic, payload):
        self.published.append((topic, json.loads(payload)))
        return types.SimpleNamespace(rc=0)

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

# --- SETUP TEST ENVIRONMENT ---
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

    # Empties the Prometheus global registry to avoid conflicts between tests
    collectors = list(REGISTRY._collector_to_names.keys())
    for collector in collectors:
        REGISTRY.unregister(collector)

    if "trust_engine" in sys.modules:
        del sys.modules["trust_engine"]

    module = importlib.import_module("trust_engine")
    monkeypatch.setattr(module, "DB_PATH", str(tmp_path / "gateway.db"))
    module.init_db()
    return module

def _insert_device(module, node_id, public_key="PUB", trust_score=100.0, status=0, peak_power=3000.0, recent_violations=0, last_sequence=0):
    with closing(sqlite3.connect(module.DB_PATH)) as conn:
        conn.execute(
            """
            INSERT INTO devices (node_id, public_key, trust_score, status, peak_power, recent_violations, last_sequence)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (node_id, public_key, trust_score, status, peak_power, recent_violations, last_sequence),
        )
        conn.commit()

def _create_signed_payload(private_key, node_id, timestamp, production, seq=1):
    payload = {
        "node_id": node_id,
        "timestamp": int(timestamp),
        "seq": seq,
        "production": float(production),
    }
    payload_str = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
    signature = private_key.sign(payload_str.encode("utf-8"), ec.ECDSA(hashes.SHA256())).hex()
    payload["sig"] = signature
    return payload


# --- TEST BASE AND CONFIGURATIONS ---
def test_init_db_creates_canonical_schema(trust_engine_module):
    with closing(sqlite3.connect(trust_engine_module.DB_PATH)) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(devices)").fetchall()}

    assert {"node_id", "public_key", "trust_score", "status", "last_seen", "created_at", "peak_power", "recent_violations", "last_sequence"}.issubset(columns)

def test_check_device_status_and_ban(trust_engine_module):
    _insert_device(trust_engine_module, "node-ok", trust_score=88.0, status=0, peak_power=3500.0)
    _insert_device(trust_engine_module, "node-bad", status=1)

    with closing(sqlite3.connect(trust_engine_module.DB_PATH)) as conn:
        cursor = conn.cursor()
        assert trust_engine_module.get_device(cursor, "missing") is None

        device_ok = trust_engine_module.get_device(cursor, "node-ok")
        assert (device_ok["status"], device_ok["trust_score"], device_ok["peak_power"]) == (0, 88.0, 3500.0)
        assert (device_ok["recent_violations"], device_ok["last_sequence"]) == (0, 0)
        assert device_ok["observation_state"] is None
        assert device_ok["last_energy_ts"] is None

        device_bad = trust_engine_module.get_device(cursor, "node-bad")
        assert (device_bad["status"], device_bad["trust_score"]) == (1, 100.0)

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

    data = {"node_id": "node-1", "timestamp": 123, "production": 12.5}
    payload_str = json.dumps(data, separators=(",", ":"))
    valid_signature = private_key.sign(payload_str.encode(), ec.ECDSA(hashes.SHA256())).hex()
    raw = payload_str[:-1] + f',"sig":"{valid_signature}"}}'

    assert trust_engine_module.verify_integrity(public_key_pem, valid_signature, raw, data) == payload_str.encode()
    assert trust_engine_module.verify_integrity(public_key_pem, "deadbeef", raw, data) is None
    assert trust_engine_module.verify_integrity(None, valid_signature, raw, data) is None

def test_verify_integrity_uses_raw_bytes_for_firmware_floats(trust_engine_module):
    # The firmware serializes production with 2 decimals: re-serializing in Python gives 1234.5
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    signed = '{"node_id":"node-1","timestamp":123,"seq":7,"production":1234.50}'
    signature = private_key.sign(signed.encode(), ec.ECDSA(hashes.SHA256())).hex()
    raw = signed[:-1] + f',"sig":"{signature}"}}'
    data = json.loads(raw)
    data.pop("sig")

    assert trust_engine_module.verify_integrity(public_key_pem, signature, raw, data) == signed.encode()

def test_extract_signed_bytes_requires_a_single_sig_member(trust_engine_module):
    assert trust_engine_module.extract_signed_bytes('{"a":1,"sig":"ab"}') == b'{"a":1}'
    assert trust_engine_module.extract_signed_bytes('{"a":1}') is None
    assert trust_engine_module.extract_signed_bytes('{"a":1,"sig":"ab","sig":"cd"}') is None

# --- TEST FORECAST AND API ---
def test_get_fallback_yield_night_and_day(trust_engine_module, monkeypatch):
    monkeypatch.setattr(trust_engine_module, "FALLBACK_TIMEZONE", "Europe/Rome")

    # 2026-04-22 00:00 UTC = 02:00 in Rome (CEST)
    night_ts = calendar.timegm((2026, 4, 22, 0, 0, 0))
    assert trust_engine_module.get_fallback_yield(night_ts) == 0.0

    # 2026-04-22 10:00 UTC = 12:00 in Rome: peak of the sinusoid
    noon_ts = calendar.timegm((2026, 4, 22, 10, 0, 0))
    assert trust_engine_module.get_fallback_yield(noon_ts) == pytest.approx(1.0)

def test_get_current_forecast_updates_cache_on_api_success(trust_engine_module, monkeypatch):
    trust_engine_module.forecast_cache = {"timestamp": 0, "yield_percentage": 0.0}
    monkeypatch.setattr(trust_engine_module.time, "time", lambda: 2000.0)
    monkeypatch.setattr(trust_engine_module.requests, "get", lambda url, timeout: _FakeResponse(500.0))

    value = trust_engine_module.get_current_forecast()

    assert value == pytest.approx(0.5)
    assert trust_engine_module.forecast_cache["yield_percentage"] == pytest.approx(0.5)
    assert trust_engine_module.forecast_cache["timestamp"] == 2000.0

def test_get_current_forecast_uses_cache_without_new_http_call(trust_engine_module, monkeypatch):
    # Same 15-minute slot (2000 // 900 == 1900 // 900): no new request
    trust_engine_module.forecast_cache = {"timestamp": 1900.0, "slot": 2, "source": "api", "kc": None, "yield_percentage": 0.77}
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

def test_forecast_tolerance_follows_the_sky(trust_engine_module):
    te = trust_engine_module
    assert te.forecast_tolerance(1.0) == pytest.approx(te.TOL_CLEAR)
    assert te.forecast_tolerance(0.0) == pytest.approx(te.TOL_CLOUDY)
    assert te.forecast_tolerance(0.5) == pytest.approx((te.TOL_CLEAR + te.TOL_CLOUDY) / 2)
    assert te.forecast_tolerance(None) == pytest.approx(te.TOL_CLOUDY)  # no reliable sky information
    assert te.forecast_tolerance(1.1) == pytest.approx(te.TOL_CLEAR)

def test_expected_yield_follows_the_sun_within_the_slot(trust_engine_module, monkeypatch):
    te = trust_engine_module
    monkeypatch.setattr(te, "LATITUDE", "38.3125")
    monkeypatch.setattr(te, "LONGITUDE", "16.0")
    morning = calendar.timegm((2026, 6, 21, 6, 0, 0))
    monkeypatch.setattr(te.time, "time", lambda: float(morning))
    monkeypatch.setattr(te, "get_current_forecast", lambda: 0.3)
    te.forecast_cache = {"timestamp": morning, "slot": None, "source": "api", "kc": 0.6, "yield_percentage": 0.3}

    # Same sky (kc), higher sun twenty minutes later: the expectation grows with the sun
    early, kc = te.get_expected_yield(morning)
    later, _ = te.get_expected_yield(morning + 1200)
    assert kc == 0.6
    assert later > early > 0
    assert early == pytest.approx(0.6 * te.clear_sky_ghi_wm2(te.solar_elevation_deg(morning)) / 1000)

def test_sky_index_is_unknown_with_the_sun_too_low(trust_engine_module, monkeypatch):
    te = trust_engine_module
    monkeypatch.setattr(te, "LATITUDE", "38.3125")
    monkeypatch.setattr(te, "LONGITUDE", "16.0")
    assert te.sky_index_from_yield(0.01, NIGHT) is None
    assert te.sky_index_from_yield(0.0, SUMMER_NOON) == 0.0
    assert te.sky_index_from_yield(0.9, SUMMER_NOON) == pytest.approx(
        900 / te.clear_sky_ghi_wm2(te.solar_elevation_deg(SUMMER_NOON))
    )

# --- TEST QUERY FLUX AND STATS ---
def test_get_node_stats_returns_correct_values(trust_engine_module):
    trust_engine_module.query_api.query_result = [
        _FakeTable([_FakeRecord("mean", 1450.5)]),
        _FakeTable([_FakeRecord("stddev", 120.0)]),
        _FakeTable([_FakeRecord("count", 30)]),
    ]
    mu, sigma = trust_engine_module.get_node_stats("node-1")
    assert mu == 1450.5
    assert sigma == 120.0

def test_get_node_stats_requires_enough_history(trust_engine_module):
    trust_engine_module.query_api.query_result = [
        _FakeTable([_FakeRecord("mean", 1450.5)]),
        _FakeTable([_FakeRecord("stddev", 120.0)]),
        _FakeTable([_FakeRecord("count", 3)]),
    ]
    assert trust_engine_module.get_node_stats("node-1") == (None, None)

def test_flux_string_escapes_injection(trust_engine_module):
    assert trust_engine_module._flux_string('a"b\\c${x}') == '"a\\"b\\\\c\\${x}"'

def _neighbor_tables(recent, past):
    return [
        _FakeTable([_FakeRecord("recent_mean", value, node_id=node) for node, value in recent.items()]),
        _FakeTable([_FakeRecord("past_mean", value, node_id=node) for node, value in past.items()]),
    ]

def test_check_spatial_anomaly_detects_drops(trust_engine_module):
    # A minimum quorum of trusted neighbors is needed
    _insert_device(trust_engine_module, "neighbor-1", trust_score=90.0, status=0)
    _insert_device(trust_engine_module, "neighbor-2", trust_score=85.0, status=0)
    _insert_device(trust_engine_module, "neighbor-3", trust_score=70.0, status=0)
    past = {"neighbor-1": 1000.0, "neighbor-2": 2000.0, "neighbor-3": 500.0}

    # Case 1: decline confirmed (recent < 85% of past) on most neighbors
    trust_engine_module.query_api.query_result = _neighbor_tables(
        {"neighbor-1": 400.0, "neighbor-2": 900.0, "neighbor-3": 480.0}, past
    )
    assert trust_engine_module.check_spatial_anomaly("node-1") is True

    # Case 2: stable production
    trust_engine_module.query_api.query_result = _neighbor_tables(
        {"neighbor-1": 950.0, "neighbor-2": 1990.0, "neighbor-3": 480.0}, past
    )
    assert trust_engine_module.check_spatial_anomaly("node-1") is False

    # Case 3: only one neighbor dropped -> no swarm consensus
    trust_engine_module.query_api.query_result = _neighbor_tables(
        {"neighbor-1": 100.0, "neighbor-2": 1990.0, "neighbor-3": 480.0}, past
    )
    assert trust_engine_module.check_spatial_anomaly("node-1") is False

def test_check_spatial_anomaly_requires_quorum_with_data(trust_engine_module):
    _insert_device(trust_engine_module, "neighbor-1", trust_score=90.0, status=0)
    _insert_device(trust_engine_module, "neighbor-2", trust_score=85.0, status=0)
    _insert_device(trust_engine_module, "neighbor-3", trust_score=70.0, status=0)

    # Registered quorum, but only two neighbors reported in both windows
    trust_engine_module.query_api.query_result = _neighbor_tables(
        {"neighbor-1": 100.0, "neighbor-2": 100.0},
        {"neighbor-1": 1000.0, "neighbor-2": 1000.0},
    )
    assert trust_engine_module.check_spatial_anomaly("node-1") is False

def test_check_spatial_anomaly_fails_below_quorum(trust_engine_module):
    # Only 2 trusted neighbors, below the threshold
    _insert_device(trust_engine_module, "neighbor-1", trust_score=90.0, status=0)
    _insert_device(trust_engine_module, "neighbor-2", trust_score=85.0, status=0)

    trust_engine_module.query_api.query_result = [
        _FakeTable([
            _FakeRecord("recent_mean", 400.0),
            _FakeRecord("past_mean", 1000.0)
        ])
    ]
    assert trust_engine_module.check_spatial_anomaly("node-1") is False


def test_check_spatial_anomaly_ignores_untrusted_neighbors(trust_engine_module):
    # 3 neighbors but with low trust score
    _insert_device(trust_engine_module, "neighbor-1", trust_score=50.0, status=0)
    _insert_device(trust_engine_module, "neighbor-2", trust_score=40.0, status=0)
    _insert_device(trust_engine_module, "neighbor-3", trust_score=55.0, status=0)

    trust_engine_module.query_api.query_result = [
        _FakeTable([
            _FakeRecord("recent_mean", 400.0),
            _FakeRecord("past_mean", 1000.0)
        ])
    ]
    assert trust_engine_module.check_spatial_anomaly("node-1") is False

# --- TEST ON_MESSAGE ---
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
        "seq": 1,
        "production": 1000.0,
        "sig": "00",
    }

    trust_engine_module.on_message(None, None, _DummyMsg(payload))
    with closing(sqlite3.connect(trust_engine_module.DB_PATH)) as conn:
        trust_score = conn.execute("SELECT trust_score FROM devices WHERE node_id = ?", ("node-1",)).fetchone()[0]
    
    assert trust_score == 100.0
    assert trust_engine_module.write_api.calls == []

def test_on_message_rejects_unregistered_device(trust_engine_module, monkeypatch):
    monkeypatch.setattr(trust_engine_module, "verify_integrity", lambda *args, **kwargs: True)
    msg = _DummyMsg({"node_id": "node-missing", "timestamp": int(time.time()), "seq": 1, "production": 1.0, "sig": "00"})
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

def test_on_message_handles_invalid_json(trust_engine_module):
    trust_engine_module.on_message(None, None, _RawMsg(b"not-json"))
    assert trust_engine_module.write_api.calls == []

def test_on_message_handles_value_error(trust_engine_module):
    msg = _DummyMsg({"node_id": "node-1", "timestamp": int(time.time()), "seq": 1, "production": "abc", "sig": "00"})
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

    assert trust_score == 0.0
    assert status == 1
    assert trust_engine_module.write_api.calls == []

def test_on_message_temporal_anomaly_scales_with_severity(trust_engine_module, monkeypatch):
    monkeypatch.setattr(trust_engine_module, "TIME_WINDOW", 60)
    monkeypatch.setattr(trust_engine_module, "TRUST_THRESHOLD_BAN", 5.0)

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    _insert_device(trust_engine_module, "node-1", public_key=public_key_pem, trust_score=100.0, status=0)

    old_ts = int(time.time()) - 90
    msg = _DummyMsg(_create_signed_payload(private_key, "node-1", old_ts, 1.0))
    trust_engine_module.on_message(None, None, msg)

    with closing(sqlite3.connect(trust_engine_module.DB_PATH)) as conn:
        trust_score = conn.execute(
            "SELECT trust_score FROM devices WHERE node_id = ?", ("node-1",)
        ).fetchone()[0]
        
    assert trust_score == pytest.approx(100.0 - (trust_engine_module.TRUST_PENALTY * 1.5))

def test_on_message_rejects_replay(risk_matrix_setup, monkeypatch):
    private_key, engine = risk_matrix_setup
    monkeypatch.setattr(engine, "get_expected_yield", lambda ts: (0.5, 1.0))

    payload = _create_signed_payload(private_key, "node-test", int(time.time()), 1400.0, seq=5)
    engine.on_message(None, None, _DummyMsg(payload))

    # Replay of the exact same message
    engine.on_message(None, None, _DummyMsg(payload))

    assert len(engine.write_api.calls) == 1  # only the first one is accepted

def test_on_message_rejects_out_of_order_sequence(risk_matrix_setup, monkeypatch):
    private_key, engine = risk_matrix_setup
    monkeypatch.setattr(engine, "get_expected_yield", lambda ts: (0.5, 1.0))

    msg1 = _DummyMsg(_create_signed_payload(private_key, "node-test", int(time.time()), 1400.0, seq=10))
    engine.on_message(None, None, msg1)

    # Lower seq than the previous one: rejected
    msg2 = _DummyMsg(_create_signed_payload(private_key, "node-test", int(time.time()), 1400.0, seq=8))
    engine.on_message(None, None, msg2)

    assert len(engine.write_api.calls) == 1

def test_on_message_rejects_missing_sequence(risk_matrix_setup, monkeypatch):
    private_key, engine = risk_matrix_setup

    payload = {
        "node_id": "node-test",
        "timestamp": int(time.time()),
        "production": 1400.0,
    }
    payload_str = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
    payload["sig"] = private_key.sign(payload_str.encode(), ec.ECDSA(hashes.SHA256())).hex()

    engine.on_message(None, None, _DummyMsg(payload))
    assert engine.write_api.calls == []

# --- TEST RISK MATRIX AND COMMS ---
# Fixed clock for the risk-matrix tests: 30 s after the start of a 15-minute window, so that
# messages a few seconds earlier share the window and moving the clock by +900 s closes it
CLOCK = {"now": 0.0}

@pytest.fixture
def risk_matrix_setup(trust_engine_module, monkeypatch):
    """Common setup for the risk-matrix branches"""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    # Peak power = 3000W, starting from trust 90.0 to test self-healing
    _insert_device(trust_engine_module, "node-test", public_key=public_key_pem, trust_score=90.0, status=0, peak_power=3000.0)

    # The sun-position bounds are covered separately with fixed timestamps
    monkeypatch.setattr(trust_engine_module, "clear_sky_limit", lambda peak, ts: float("inf"))
    monkeypatch.setattr(trust_engine_module, "physical_production_cap", lambda peak, ts: float("inf"))

    window = trust_engine_module.WINDOW_SECONDS
    CLOCK["now"] = float(1_800_000_000 - 1_800_000_000 % window + 30)
    monkeypatch.setattr(trust_engine_module.time, "time", lambda: CLOCK["now"])

    return private_key, trust_engine_module

def _send(engine, private_key, production, seq, offset=0):
    """Signed message from node-test, `offset` seconds from the fixed clock."""
    payload = _create_signed_payload(private_key, "node-test", int(CLOCK["now"]) + offset, production, seq=seq)
    engine.on_message(None, None, _DummyMsg(payload))

def _close_window(engine, private_key, production, seq):
    """Move the clock to the next 15-minute window and send one message there, closing the current one."""
    CLOCK["now"] += engine.WINDOW_SECONDS
    _send(engine, private_key, production, seq)

def _trust(engine):
    with closing(sqlite3.connect(engine.DB_PATH)) as conn:
        return conn.execute("SELECT trust_score FROM devices WHERE node_id = 'node-test'").fetchone()[0]

def test_on_message_meteo_valid_triggers_self_healing_once_per_window(risk_matrix_setup, monkeypatch):
    private_key, engine = risk_matrix_setup

    # Clear sky, forecast of 0.5 (expected 1500W, tolerance 10%)
    monkeypatch.setattr(engine, "get_expected_yield", lambda ts: (0.5, 1.0))

    _send(engine, private_key, 1400.0, seq=1, offset=-20)
    _send(engine, private_key, 1400.0, seq=2)
    assert _trust(engine) == 90.0 # recovery is earned by a clean window, not by each message

    _close_window(engine, private_key, 1400.0, seq=3)
    assert _trust(engine) == 92.0 # 90.0 + 2.0 (Self-healing)
    assert len(engine.write_api.calls) == 3

def test_on_message_window_overproduction_applies_penalty(risk_matrix_setup, monkeypatch):
    private_key, engine = risk_matrix_setup

    # Clear sky, forecast of 0.2 (expected 600W): allowed 600W + 60W band
    monkeypatch.setattr(engine, "get_expected_yield", lambda ts: (0.2, 1.0))

    # 2500W for the whole window: a single value could be the sun between clouds, the energy cannot
    _send(engine, private_key, 2500.0, seq=1, offset=-20)
    _send(engine, private_key, 2500.0, seq=2)
    assert _trust(engine) == 90.0
    assert engine.write_api.calls[-1]["record"].fields["status"] == "above_forecast"

    _close_window(engine, private_key, 600.0, seq=3)

    trust_score, _, _, violations, _ = _node_state(engine)
    assert trust_score == 75.0 # 90.0 - 15.0, once for the window
    assert violations == 1
    assert REGISTRY.get_sample_value("te_penalties_applied_total", {"reason": "window_overproduction"}) == 1.0

def test_on_message_sun_between_clouds_is_not_penalized(risk_matrix_setup, monkeypatch):
    private_key, engine = risk_matrix_setup

    # Expected 1500W, band 150W: bursts at 2400W balanced by shaded moments at 800W
    monkeypatch.setattr(engine, "get_expected_yield", lambda ts: (0.5, 1.0))
    for seq, (offset, production) in enumerate([(-40, 1500.0), (-30, 2400.0), (-20, 800.0), (-10, 2400.0), (0, 800.0)], 1):
        _send(engine, private_key, production, seq=seq, offset=offset)

    _close_window(engine, private_key, 1500.0, seq=6)

    trust_score, _, _, violations, _ = _node_state(engine)
    assert (trust_score, violations) == (92.0, 0)

def test_on_message_tolerance_is_wider_with_clouds(risk_matrix_setup, monkeypatch):
    private_key, engine = risk_matrix_setup

    # 1900W against an expected 1500W (+27%): fraud with a clear sky, plausible with clouds
    monkeypatch.setattr(engine, "get_expected_yield", lambda ts: (0.5, 0.4))  # tolerance 52%
    _send(engine, private_key, 1900.0, seq=1, offset=-20)
    _send(engine, private_key, 1900.0, seq=2)

    # Clear sky from now on (tolerance 10%); 1650W is exactly at the edge, leaving no slack
    monkeypatch.setattr(engine, "get_expected_yield", lambda ts: (0.5, 1.0))
    _close_window(engine, private_key, 1650.0, seq=3)
    assert _trust(engine) == 92.0

    _send(engine, private_key, 1900.0, seq=4, offset=10)
    _send(engine, private_key, 1900.0, seq=5, offset=30)
    _close_window(engine, private_key, 1650.0, seq=6)
    assert _trust(engine) == 77.0

def test_on_message_consistent_degradation_is_accepted(risk_matrix_setup, monkeypatch):
    private_key, engine = risk_matrix_setup

    # Simulates forecast of 0.8 (expected 2400W)
    monkeypatch.setattr(engine, "get_expected_yield", lambda ts: (0.8, 1.0))

    # Simulates a degraded historic (avg: 1200W, stddev: 50.0)
    monkeypatch.setattr(engine, "get_node_stats", lambda n: (1200.0, 50.0))
    monkeypatch.setattr(engine, "check_spatial_anomaly", lambda n: False)

    # Production 1100W (fails the weather check, but Z-Score = -2.0) -> "ok_degradation"
    _send(engine, private_key, 1100.0, seq=1)

    assert _trust(engine) == 90.0
    assert engine.write_api.calls[0]["record"].fields["status"] == "ok_degradation"

def test_on_message_swarm_validation_is_accepted(risk_matrix_setup, monkeypatch):
    private_key, engine = risk_matrix_setup

    # Simulates forecast of 0.8 (expected 2400W)
    monkeypatch.setattr(engine, "get_expected_yield", lambda ts: (0.8, 1.0))

    # Simulates an high historical (avg: 2300W, stddev: 100.0)
    monkeypatch.setattr(engine, "get_node_stats", lambda n: (2300.0, 100.0))

    # Simulates overall decline in the neighborhood
    monkeypatch.setattr(engine, "check_spatial_anomaly", lambda n: True)

    # Production 500W (fails weather check, Z-Score = -18.0) -> "ok_neigh"
    _send(engine, private_key, 500.0, seq=1)

    assert _trust(engine) == 90.0
    assert engine.write_api.calls[0]["record"].fields["status"] == "ok_neigh"

def _node_state(engine):
    with closing(sqlite3.connect(engine.DB_PATH)) as conn:
        return conn.execute(
            """SELECT trust_score, observation_state, observation_counter, recent_violations, status
               FROM devices WHERE node_id = 'node-test'"""
        ).fetchone()

def test_on_message_isolated_drop_is_credited_and_monitored(risk_matrix_setup, monkeypatch):
    private_key, engine = risk_matrix_setup

    # Simulates forecast of 0.8 (expected 2400W)
    monkeypatch.setattr(engine, "get_expected_yield", lambda ts: (0.8, 1.0))
    monkeypatch.setattr(engine, "get_node_stats", lambda n: (2300.0, 100.0))

    # Simulates no decline in the neighborhood
    monkeypatch.setattr(engine, "check_spatial_anomaly", lambda n: False)

    # Production 500W (fails weather check, Z-score high, neighborhood stable) -> "local_drop"
    msg = _DummyMsg(_create_signed_payload(private_key, "node-test", int(time.time()), 500.0))
    engine.on_message(None, None, msg)

    trust_score, state, counter, violations, _ = _node_state(engine)
    assert trust_score == 90.0 # declaring less is never penalized (recovery comes at window close)
    assert (state, counter, violations) == ("local_anomaly", 1, 0)
    assert len(engine.write_api.calls) == 1 # credited as declared
    assert engine.write_api.calls[0]["record"].fields["status"] == "local_drop"

def test_on_message_persistent_local_drop_raises_maintenance_alert(risk_matrix_setup, monkeypatch):
    private_key, engine = risk_matrix_setup
    monkeypatch.setattr(engine, "get_expected_yield", lambda ts: (0.8, 1.0))
    monkeypatch.setattr(engine, "get_node_stats", lambda n: (2300.0, 100.0))
    monkeypatch.setattr(engine, "check_spatial_anomaly", lambda n: False)
    monkeypatch.setattr(engine, "LOCAL_DROP_OBSERVATION_LIMIT", 3)

    with closing(sqlite3.connect(engine.DB_PATH)) as conn:
        conn.execute(
            """UPDATE devices SET observation_state = 'local_anomaly', observation_counter = 2,
               observation_since = datetime('now', '-30 minutes') WHERE node_id = 'node-test'"""
        )
        conn.commit()

    msg = _DummyMsg(_create_signed_payload(private_key, "node-test", int(time.time()), 500.0))
    engine.on_message(None, None, msg)

    trust_score, state, _, violations, _ = _node_state(engine)
    assert trust_score == 90.0
    assert state == "maintenance_suspected"
    assert violations == 0
    assert len(engine.write_api.calls) == 1
    assert REGISTRY.get_sample_value("te_maintenance_alerts_total", {"reason": "local_drop"}) == 1.0

def test_on_message_new_building_shadow_never_bans(risk_matrix_setup, monkeypatch):
    # A building permanently cuts the production to ~30%: hours of local drops must not ban the node
    private_key, engine = risk_matrix_setup
    monkeypatch.setattr(engine, "get_expected_yield", lambda ts: (0.8, 1.0))  # expected 2400W
    monkeypatch.setattr(engine, "get_node_stats", lambda n: (2300.0, 50.0))  # history before the building
    monkeypatch.setattr(engine, "check_spatial_anomaly", lambda n: False)
    monkeypatch.setattr(engine, "LOCAL_DROP_OBSERVATION_LIMIT", 3)

    # The building appeared half an hour ago
    with closing(sqlite3.connect(engine.DB_PATH)) as conn:
        conn.execute(
            """UPDATE devices SET observation_state = 'local_anomaly', observation_counter = 0,
               observation_since = datetime('now', '-30 minutes') WHERE node_id = 'node-test'"""
        )
        conn.commit()

    now = int(time.time())
    for seq in range(1, 41):
        payload = _create_signed_payload(private_key, "node-test", now - 30 + seq, 700.0, seq=seq)
        engine.on_message(None, None, _DummyMsg(payload))

    trust_score, state, _, violations, status = _node_state(engine)
    assert status == 0
    assert violations == 0
    assert trust_score == 90.0
    assert state == "maintenance_suspected"
    assert len(engine.write_api.calls) == 40

def test_on_message_normal_value_clears_observation(risk_matrix_setup, monkeypatch):
    private_key, engine = risk_matrix_setup
    monkeypatch.setattr(engine, "get_expected_yield", lambda ts: (0.5, 1.0))

    with closing(sqlite3.connect(engine.DB_PATH)) as conn:
        conn.execute(
            """UPDATE devices SET observation_state = 'local_anomaly', observation_counter = 5,
               observation_since = datetime('now', '-3 days') WHERE node_id = 'node-test'"""
        )
        conn.commit()

    msg = _DummyMsg(_create_signed_payload(private_key, "node-test", int(time.time()), 1400.0))
    engine.on_message(None, None, msg)

    with closing(sqlite3.connect(engine.DB_PATH)) as conn:
        state, counter, since = conn.execute(
            "SELECT observation_state, observation_counter, observation_since FROM devices WHERE node_id = 'node-test'"
        ).fetchone()

    assert (state, counter, since) == (None, 0, None)

def test_on_message_low_production_is_credited_without_penalty(risk_matrix_setup, monkeypatch):
    private_key, engine = risk_matrix_setup
    monkeypatch.setattr(engine, "get_expected_yield", lambda ts: (0.8, 1.0))  # expected 2400W, floor 240W

    msg = _DummyMsg(_create_signed_payload(private_key, "node-test", int(time.time()), 100.0))
    engine.on_message(None, None, msg)

    trust_score, state, _, violations, _ = _node_state(engine)
    assert trust_score == 90.0
    assert violations == 0
    assert state == "local_anomaly"
    assert engine.write_api.calls[0]["record"].fields["status"] == "low_production"

@pytest.mark.parametrize("raw_production", ["NaN", "Infinity", "-5.0"])
def test_on_message_rejects_non_physical_production(risk_matrix_setup, monkeypatch, raw_production):
    private_key, engine = risk_matrix_setup
    monkeypatch.setattr(engine, "get_expected_yield", lambda ts: (0.5, 1.0))

    signed = f'{{"node_id":"node-test","timestamp":{int(time.time())},"seq":1,"production":{raw_production}}}'
    signature = private_key.sign(signed.encode(), ec.ECDSA(hashes.SHA256())).hex()
    raw = signed[:-1] + f',"sig":"{signature}"}}'

    engine.on_message(None, None, _RawMsg(raw.encode()))

    with closing(sqlite3.connect(engine.DB_PATH)) as conn:
        trust_score = conn.execute("SELECT trust_score FROM devices WHERE node_id = 'node-test'").fetchone()[0]

    assert trust_score == 90.0
    assert engine.write_api.calls == []

def test_on_message_accepts_firmware_payload_and_integrates_energy(risk_matrix_setup, monkeypatch):
    private_key, engine = risk_matrix_setup
    monkeypatch.setattr(engine, "get_expected_yield", lambda ts: (0.5, 1.0))  # expected 1500W
    client = _FakeMqttClient()
    now = int(time.time())

    def firmware_message(ts, seq, production_str):
        signed = f'{{"node_id":"node-test","timestamp":{ts},"seq":{seq},"production":{production_str}}}'
        signature = private_key.sign(signed.encode(), ec.ECDSA(hashes.SHA256())).hex()
        return signed, _RawMsg((signed[:-1] + f',"sig":"{signature}"}}').encode())

    # First message: no previous timestamp, so nothing is credited on the ledger
    _, first = firmware_message(now - 10, 1, "1400.50")
    engine.on_message(client, None, first)
    assert client.published == []
    assert len(engine.write_api.calls) == 1

    # Second message, 10 s later, with a trailing zero that Python would re-serialize differently
    signed, second = firmware_message(now, 2, "1440.00")
    engine.on_message(client, None, second)

    assert len(engine.write_api.calls) == 2
    assert len(client.published) == 1
    topic, transfer = client.published[0]
    assert topic == engine.TRANSFERS_TOPIC
    assert transfer["interval_s"] == 10.0
    assert transfer["power_w"] == 1440.0
    assert transfer["wh_amount"] == pytest.approx(1440.0 * 10 / 3600)
    assert transfer["seq"] == 2
    assert transfer["signed_payload"] == signed

def test_on_message_caps_energy_interval(risk_matrix_setup, monkeypatch):
    private_key, engine = risk_matrix_setup
    monkeypatch.setattr(engine, "get_expected_yield", lambda ts: (0.5, 1.0))
    monkeypatch.setattr(engine, "MAX_ENERGY_INTERVAL_S", 30.0)
    client = _FakeMqttClient()

    with closing(sqlite3.connect(engine.DB_PATH)) as conn:
        conn.execute("UPDATE devices SET last_energy_ts = ? WHERE node_id = 'node-test'", (int(time.time()) - 3600,))
        conn.commit()

    msg = _DummyMsg(_create_signed_payload(private_key, "node-test", int(time.time()), 1400.0))
    engine.on_message(client, None, msg)

    assert client.published[0][1]["interval_s"] == 30.0

def test_on_message_unsynced_clock_is_rejected_without_penalty(risk_matrix_setup):
    private_key, engine = risk_matrix_setup

    msg = _DummyMsg(_create_signed_payload(private_key, "node-test", 0, 1400.0))
    engine.on_message(None, None, msg)

    with closing(sqlite3.connect(engine.DB_PATH)) as conn:
        trust_score, violations = conn.execute(
            "SELECT trust_score, recent_violations FROM devices WHERE node_id = 'node-test'"
        ).fetchone()

    assert (trust_score, violations) == (90.0, 0)
    assert engine.write_api.calls == []

def test_on_message_temporal_violation_records_violation_time(risk_matrix_setup):
    private_key, engine = risk_matrix_setup

    msg = _DummyMsg(_create_signed_payload(private_key, "node-test", int(time.time()) - 600, 1400.0))
    engine.on_message(None, None, msg)

    with closing(sqlite3.connect(engine.DB_PATH)) as conn:
        violations, last_violation = conn.execute(
            "SELECT recent_violations, last_violation_time FROM devices WHERE node_id = 'node-test'"
        ).fetchone()

    assert violations == 1
    assert last_violation is not None

def test_on_message_recovery_decays_after_violations(risk_matrix_setup, monkeypatch):
    private_key, engine = risk_matrix_setup

    # The node already has 2 recent violations -> decay_factor = 0.25 -> bonus = 0.5
    with closing(sqlite3.connect(engine.DB_PATH)) as conn:
        conn.execute("UPDATE devices SET recent_violations = 2 WHERE node_id = 'node-test'")
        conn.commit()

    monkeypatch.setattr(engine, "get_expected_yield", lambda ts: (0.5, 1.0))  # expected 1500W

    # Two messages: the window needs a measured interval to earn the recovery
    _send(engine, private_key, 1400.0, seq=1, offset=-20)
    _send(engine, private_key, 1400.0, seq=2)
    _close_window(engine, private_key, 1400.0, seq=3)

    assert _trust(engine) == 90.5  # 90.0 + (2.0 * 0.25) instead of the full +2.0

def test_on_message_recovery_bonus_caps_at_max_decay(risk_matrix_setup, monkeypatch):
    private_key, engine = risk_matrix_setup

    # 10 violations
    with closing(sqlite3.connect(engine.DB_PATH)) as conn:
        conn.execute("UPDATE devices SET recent_violations = 10 WHERE node_id = 'node-test'")
        conn.commit()

    monkeypatch.setattr(engine, "get_expected_yield", lambda ts: (0.5, 1.0))

    # Two messages: the window needs a measured interval to earn the recovery
    _send(engine, private_key, 1400.0, seq=1, offset=-20)
    _send(engine, private_key, 1400.0, seq=2)
    _close_window(engine, private_key, 1400.0, seq=3)

    # decay_factor = 0.5**5 = 0.03125 -> bonus = 0.0625
    assert _trust(engine) == pytest.approx(90.0625)

# --- TEST PHYSICAL CAP (SUN POSITION) ---
SUMMER_NOON = calendar.timegm((2026, 6, 21, 10, 58, 0))   # solar noon at lon 16E
WINTER_NOON = calendar.timegm((2026, 12, 21, 10, 58, 0))
WINTER_DUSK = calendar.timegm((2026, 12, 21, 15, 40, 0))  # sun just below the horizon
NIGHT = calendar.timegm((2026, 6, 21, 0, 0, 0))

def test_solar_elevation_matches_astronomy(trust_engine_module):
    te = trust_engine_module
    # Noon elevation = 90 - latitude +/- 23.44 at the solstices
    assert te.solar_elevation_deg(SUMMER_NOON, 38.3125, 16.0) == pytest.approx(90 - 38.3125 + 23.44, abs=0.5)
    assert te.solar_elevation_deg(WINTER_NOON, 38.3125, 16.0) == pytest.approx(90 - 38.3125 - 23.44, abs=0.5)
    assert te.solar_elevation_deg(NIGHT, 38.3125, 16.0) < -20

def test_physical_cap_by_time_of_day(trust_engine_module, monkeypatch):
    te = trust_engine_module
    monkeypatch.setattr(te, "LATITUDE", "38.3125")
    monkeypatch.setattr(te, "LONGITUDE", "16.0")

    # Night: only meter noise
    assert te.physical_production_cap(3000.0, NIGHT) == te.NIGHT_MAX_WATT
    assert te.clear_sky_limit(3000.0, NIGHT) == 0.0

    # Noon: bounded by the nameplate overload
    assert te.physical_production_cap(3000.0, SUMMER_NOON) == pytest.approx(3000.0 * te.PEAK_OVERLOAD_RATIO)

    # Twilight: small but non-zero, so an honest meter is not penalized at sunset
    dusk_cap = te.physical_production_cap(3000.0, WINTER_DUSK)
    assert te.NIGHT_MAX_WATT < dusk_cap < 150.0

    # The cap grows with the sun
    assert te.max_irradiance_wm2(5.0) < te.max_irradiance_wm2(30.0) < te.max_irradiance_wm2(70.0)

@pytest.fixture
def night_setup(trust_engine_module, monkeypatch):
    """Node at a fixed night instant, with the real sun-position bounds."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    _insert_device(trust_engine_module, "node-test", public_key=public_key_pem, trust_score=90.0, peak_power=3000.0)

    monkeypatch.setattr(trust_engine_module, "LATITUDE", "38.3125")
    monkeypatch.setattr(trust_engine_module, "LONGITUDE", "16.0")
    monkeypatch.setattr(trust_engine_module.time, "time", lambda: float(NIGHT))
    return private_key, trust_engine_module

def test_on_message_night_production_is_penalized(night_setup, monkeypatch):
    private_key, engine = night_setup
    monkeypatch.setattr(engine, "get_expected_yield", lambda ts: (0.0, 1.0))

    # 90W was inside the old 100W night tolerance: now it is above the physical cap
    engine.on_message(None, None, _DummyMsg(_create_signed_payload(private_key, "node-test", NIGHT, 90.0)))

    trust_score, _, _, violations, _ = _node_state(engine)
    assert trust_score == 75.0
    assert violations == 1
    assert engine.write_api.calls == []

def test_on_message_night_meter_noise_is_accepted(night_setup, monkeypatch):
    private_key, engine = night_setup
    monkeypatch.setattr(engine, "get_expected_yield", lambda ts: (0.0, 1.0))

    engine.on_message(None, None, _DummyMsg(_create_signed_payload(private_key, "node-test", NIGHT, 3.0)))

    trust_score, _, _, violations, _ = _node_state(engine)
    assert (trust_score, violations) == (90.0, 0)
    assert engine.write_api.calls[0]["record"].fields["status"] == "ok_meteo"

def test_on_message_stale_forecast_after_sunset_is_ignored(night_setup, monkeypatch):
    private_key, engine = night_setup
    # The cached forecast still says 10% (300W) but the sun has set: honest 0W is normal
    monkeypatch.setattr(engine, "get_expected_yield", lambda ts: (0.1, 1.0))

    engine.on_message(None, None, _DummyMsg(_create_signed_payload(private_key, "node-test", NIGHT, 0.0)))

    trust_score, state, _, _, _ = _node_state(engine)
    assert trust_score == 90.0
    assert state is None  # no spurious "low_production" anomaly every evening
    assert engine.write_api.calls[0]["record"].fields["status"] == "ok_meteo"

# --- TEST CONNECTION AND PROTOCOLS ---
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