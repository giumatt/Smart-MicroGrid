"""
Trust Engine for Smart MicroGrid
Validates telemetry messages through cryptographic, temporal, and meteorological checks.
Manages device trust scores, self-healing, and banning logic.
"""
import json
import logging
import math
import os
import re
import sqlite3
import time
from contextlib import closing
from datetime import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import paho.mqtt.client as mqtt
import requests
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from prometheus_client import start_http_server, Counter, Histogram

# --- Setup Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("TrustEngine")

# --- CONFIGURATION ---
MQTT_BROKER = os.getenv("MQTT_BROKER", "mosquitto")
MQTT_TOPIC = os.getenv("MQTT_TOPIC", "microgrid/production/#")
MQTT_PORT = int(os.getenv("MQTT_PORT", "8883"))
CERTS_PATH = os.getenv("CERTS_PATH", "/app/certs")
MQTT_USE_TLS = os.getenv("MQTT_USE_TLS", "true").strip().lower() in {"1", "true", "yes", "on"}
MQTT_TLS_CA_CERT = os.getenv("MQTT_TLS_CA_CERT", f"{CERTS_PATH}/ca.crt")
MQTT_TLS_CERT = os.getenv("MQTT_TLS_CERT", f"{CERTS_PATH}/nodered.crt")
MQTT_TLS_KEY = os.getenv("MQTT_TLS_KEY", f"{CERTS_PATH}/nodered.key")
DB_PATH = os.getenv("DB_PATH", "/app/data/gateway.db")
TRANSFERS_TOPIC = os.getenv("BLOCKCHAIN_MQTT_TOPIC", "microgrid/transfers")
TRANSFER_TO_NODE = os.getenv("TRANSFER_TO_NODE", "grid")
MIN_SPATIAL_QUORUM = int(os.getenv("MIN_SPATIAL_QUORUM", "3"))
LOCAL_DROP_OBSERVATION_LIMIT = int(os.getenv("LOCAL_DROP_OBSERVATION_LIMIT", "12"))
LOCAL_DROP_OBSERVATION_WINDOW_MIN = int(os.getenv("LOCAL_DROP_OBSERVATION_WINDOW_MIN", "10"))

# InfluxDB Configuration
INFLUX_URL = os.getenv("INFLUXDB_URL", "http://influxdb:8086")
INFLUX_TOKEN = os.getenv("INFLUXDB_TOKEN", "microgrid-secret-token")
INFLUX_ORG = os.getenv("INFLUXDB_ORG", "microgrid")
INFLUX_BUCKET = os.getenv("INFLUXDB_BUCKET", "telemetry")

# Trust Parameters
TIME_WINDOW = int(os.getenv("TIME_WINDOW", "60"))
TRUST_THRESHOLD_BAN = float(os.getenv("TRUST_THRESHOLD_BAN", "20.0"))
TRUST_PENALTY = float(os.getenv("TRUST_PENALTY", "15.0"))
TRUST_RECOVERY_BONUS = float(os.getenv("TRUST_RECOVERY_BONUS", "2.0"))
# Dynamic meteorological tolerance: tight when the forecast says clear sky,
# wide with clouds or without a forecast (not reliable). It is checked on the energy of
# 15-minute windows, the same resolution of the forecast
TOL_CLEAR = float(os.getenv("TOL_CLEAR", "0.10"))
TOL_CLOUDY = float(os.getenv("TOL_CLOUDY", "0.80"))
ABS_TOLERANCE_RATIO = float(os.getenv("ABS_TOLERANCE_RATIO", "0.02")) # minimum band, fraction of peak power
WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "900"))
FORECAST_SLOT_SECONDS = 900          # Open-Meteo "current" data changes every 15 minutes
KC_MIN_CLEAR_GHI = 50.0              # below this clear-sky irradiance the sky index is not reliable
KC_MAX = 1.2
MIN_EFFICIENCY_RATIO = float(os.getenv("MIN_EFFICIENCY_RATIO", "0.10"))
SUDDEN_DROP_Z_SCORE = float(os.getenv("SUDDEN_DROP_Z_SCORE", "3.0"))
TEMPORAL_MAX_MULTIPLIER = float(os.getenv("TEMPORAL_MAX_MULTIPLIER", "2.0"))

STATS_WINDOW_MIN = int(os.getenv("STATS_WINDOW_MIN", "60"))
STATS_MIN_SAMPLES = int(os.getenv("STATS_MIN_SAMPLES", "10"))
SPATIAL_DROP_RATIO = float(os.getenv("SPATIAL_DROP_RATIO", "0.85"))

# Energy accounting: each accepted message credits power * elapsed time since the previous one,
# capped so that connection gaps are not credited as continuous production
MAX_ENERGY_INTERVAL_S = float(os.getenv("MAX_ENERGY_INTERVAL_S", "300"))

# Timestamps before this value means the device clock was never synchronized
MIN_VALID_TIMESTAMP = 1600000000

# Ground Truth Location (Default:
LATITUDE = os.getenv("LATITUDE")
LONGITUDE = os.getenv("LONGITUDE")
FALLBACK_TIMEZONE = os.getenv("FALLBACK_TIMEZONE", "Europe/Rome")

# Physical cap: highest production allowed by the sun position, whatever the weather API says
NIGHT_ELEVATION_DEG = float(os.getenv("NIGHT_ELEVATION_DEG", "-2.0"))   # sun below this: night
NIGHT_MAX_WATT = float(os.getenv("NIGHT_MAX_WATT", "5.0"))              # meter noise allowed at night
MAX_DIFFUSE_WM2 = float(os.getenv("MAX_DIFFUSE_WM2", "120.0"))          # diffuse + ground-reflected allowance
CLOUD_ENHANCEMENT_MARGIN = float(os.getenv("CLOUD_ENHANCEMENT_MARGIN", "1.3")) # sun between clouds can exceed clear sky
PEAK_OVERLOAD_RATIO = float(os.getenv("PEAK_OVERLOAD_RATIO", "1.1"))    # output never above ~nameplate

# --- PROMETHEUS METRICS DEFINITIONS ---
TE_MSG_RECEIVED = Counter('te_messages_received_total', 'Total MQTT telemetry messages received')
TE_MSG_ACCEPTED = Counter('te_messages_accepted_total', 'Messages successfully validated and stored')
TE_MSG_REJECTED = Counter('te_messages_rejected_total', 'Messages rejected during validation', ['reason'])
TE_PENALTY_APPLIED = Counter('te_penalties_applied_total', 'Trust penalties applied to nodes', ['reason'])
TE_PROCESSING_TIME = Histogram('te_processing_seconds', 'Time spent processing an entire message')
TE_CRYPTO_TIME = Histogram('te_crypto_validation_seconds', 'Time spent explicitly in ECDSA verification')
TE_VALIDATIONS = Counter('te_validations_total', 'Validation outcomes for telemetry', ['result', 'reason'])
TE_MAINTENANCE_ALERTS = Counter('te_maintenance_alerts_total', 'Persistent local production anomalies flagged for maintenance', ['reason'])

# Observation states of a node producing less than expected (monitoring only, no penalty)
LOCAL_ANOMALY_STATE = "local_anomaly"
MAINTENANCE_STATE = "maintenance_suspected"
LOCAL_ANOMALY_REASONS = {"local_drop", "low_production"}
# Declaring more than physically possible: the only outcome penalized on a single message
# (energy above the forecast band is penalized once per 15-minute window)
OVERCLAIM_REASONS = {"above_physical_limit"}

# --- FORECAST GROUND TRUTH ---
forecast_cache = {
    "timestamp": 0,
    "slot": None,          # 15-minute slot of the last refresh
    "source": None,        # "api" or "fallback"
    "kc": None,            # clear-sky index of the forecast (None when unknown)
    "yield_percentage": 0.0
}

# --- INFLUXDB INITIALIZATION ---
try:
    influx_client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
    write_api = influx_client.write_api(write_options=SYNCHRONOUS)
    query_api = influx_client.query_api()
    logger.info("[TRUST] InfluxDB client initialized successfully")
except Exception as e:
    logger.error(f"[TRUST] Failed to initialize InfluxDB client: {e}")
    raise

# --- SQLITE MANAGEMENT ---
DEVICE_COLUMNS = (
    "node_id", "public_key", "status", "trust_score", "peak_power", "recent_violations",
    "last_sequence", "observation_state", "observation_since", "observation_counter", "last_energy_ts",
    "window_start", "window_declared_wh", "window_allowed_wh",
)

def init_db():
    """Initialize the SQLite database."""
    migrations = [
        ("peak_power", "ALTER TABLE devices ADD COLUMN peak_power REAL DEFAULT 3000.0"),
        ("recent_violations", "ALTER TABLE devices ADD COLUMN recent_violations INTEGER DEFAULT 0"),
        ("last_sequence", "ALTER TABLE devices ADD COLUMN last_sequence INTEGER DEFAULT 0"),
        ("last_violation_time", "ALTER TABLE devices ADD COLUMN last_violation_time TIMESTAMP"),
        ("observation_state", "ALTER TABLE devices ADD COLUMN observation_state TEXT"),
        ("observation_since", "ALTER TABLE devices ADD COLUMN observation_since TIMESTAMP"),
        ("observation_counter", "ALTER TABLE devices ADD COLUMN observation_counter INTEGER DEFAULT 0"),
        ("last_energy_ts", "ALTER TABLE devices ADD COLUMN last_energy_ts INTEGER"),
        ("window_start", "ALTER TABLE devices ADD COLUMN window_start INTEGER"),
        ("window_declared_wh", "ALTER TABLE devices ADD COLUMN window_declared_wh REAL DEFAULT 0"),
        ("window_allowed_wh", "ALTER TABLE devices ADD COLUMN window_allowed_wh REAL DEFAULT 0"),
    ]

    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
            c = conn.cursor()

            c.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    node_id TEXT PRIMARY KEY,
                    public_key TEXT NOT NULL,
                    trust_score REAL DEFAULT 100.0,
                    status INTEGER DEFAULT 0,
                    last_seen TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            for column_name, sql in migrations:
                try:
                    c.execute(sql)
                    logger.info(f"[TRUST] DB Migration: Added column '{column_name}'.")
                except sqlite3.OperationalError:
                    pass

            conn.commit()
        logger.info(f"[TRUST] Database initialized/verified at {DB_PATH}")
    except Exception as e:
        logger.error(f"[TRUST] Database initialization failed: {e}")
        raise

def get_device(cursor, node_id):
    '''Return the device row as a dict, or None if the device is not registered.'''
    try:
        cursor.execute(f"SELECT {', '.join(DEVICE_COLUMNS)} FROM devices WHERE node_id = ?", (node_id,))
        row = cursor.fetchone()
        return dict(zip(DEVICE_COLUMNS, row)) if row else None
    except Exception as e:
        logger.error(f"[TRUST] Error checking device status for {node_id}: {e}")
        return None

def ban_device(cursor, node_id):
    '''Permanently ban a device by setting status = 1 in the DB'''
    try:
        cursor.execute("UPDATE devices SET status = 1 WHERE node_id = ?", (node_id,))
        logger.warning(f"[TRUST] DEVICE BANNED: {node_id} (Trust dropped below {TRUST_THRESHOLD_BAN})")
    except Exception as e:
        logger.error(f"[TRUST] Failed to ban device: {e}")

# --- CRYPTOGRAPHIC VERIFICATION ---
# The devices sign the compact JSON before appending the "sig" member, so the signed
# bytes are the received message with exactly that trailing member removed.
_SIG_MEMBER_RE = re.compile(r',\s*"sig"\s*:\s*"[0-9a-fA-F]*"')

def extract_signed_bytes(raw_text):
    """Return the exact bytes signed by the device, or None if the layout is unexpected."""
    matches = list(_SIG_MEMBER_RE.finditer(raw_text))
    if len(matches) != 1:
        return None
    match = matches[0]
    return (raw_text[:match.start()] + raw_text[match.end():]).encode('utf-8')

def verify_integrity(public_key_pem, signature_hex, raw_text, data_without_sig):
    """
    Verify the ECDSA-SHA256 signature of the payload.
    Guarantees message authenticity and integrity.
    """
    if not public_key_pem or not isinstance(signature_hex, str):
        return None

    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        signature = bytes.fromhex(signature_hex)
    except Exception as e:
        logger.error(f"[TRUST] Invalid public key or signature encoding: {e}")
        return None

    candidates = []
    raw_signed = extract_signed_bytes(raw_text)
    if raw_signed is not None:
        candidates.append(raw_signed)
    canonical = json.dumps(data_without_sig, separators=(',', ':'), ensure_ascii=True).encode('utf-8')
    if canonical not in candidates:
        candidates.append(canonical)

    with TE_CRYPTO_TIME.time():
        for candidate in candidates:
            try:
                public_key.verify(signature, candidate, ec.ECDSA(hashes.SHA256()))
                return candidate
            except Exception:
                continue
    return None

def _local_hour(now_ts):
    '''Decimal hour at the plant location, independent from the container timezone.'''
    try:
        local_dt = datetime.fromtimestamp(now_ts, ZoneInfo(FALLBACK_TIMEZONE))
    except (ZoneInfoNotFoundError, ValueError):
        logger.warning(f"[TRUST] Unknown timezone '{FALLBACK_TIMEZONE}', using the container local time")
        local_dt = datetime.fromtimestamp(now_ts)
    return local_dt.hour + (local_dt.minute / 60.0)

def get_fallback_yield(now_ts=None):
    '''
    Emergency mathematical model used if the weather APIs are offline.
    '''
    hour = _local_hour(time.time() if now_ts is None else now_ts)

    if hour < 6.0 or hour > 18.0:
        return 0.0 # Night

    # Sinusoidal curve from 06:00 to 18:00
    daylight_phase = (hour - 6.0) / 12.0
    sun_factor = math.sin(math.pi * daylight_phase)
    return max(0.0, sun_factor)

def get_current_forecast():
    '''
    Retrieve the current solar irradiance from Open-Meteo.
    Refreshed once per 15-minute slot, aligned to the clock
    so that devices and gateway read the same value. Also stores the clear-sky index kc.
    Returns the forecast yield percentage (0.0 - 1.0).
    '''
    now = time.time()
    slot = int(now // FORECAST_SLOT_SECONDS)

    if forecast_cache.get("slot") != slot:
        try:
            url = f"https://api.open-meteo.com/v1/forecast?latitude={LATITUDE}&longitude={LONGITUDE}&current=shortwave_radiation"
            response = requests.get(url, timeout=10)
            response.raise_for_status()

            data = response.json()
            radiation_w_m2 = data["current"]["shortwave_radiation"]

            # Assume a theoretical maximum irradiance of ~1000 W/m^2
            yield_pct = min(1.0, max(0.0, radiation_w_m2) / 1000.0)

            # The value is the average of the previous 15 minutes: its reference is mid-slot
            kc = sky_index_from_yield(yield_pct, now - FORECAST_SLOT_SECONDS / 2)
            forecast_cache.update(slot=slot, timestamp=now, source="api", kc=kc, yield_percentage=yield_pct)
            logger.info(
                f"[TRUST] Weather forecast updated: estimated yield {yield_pct*100:.1f}% "
                f"(Irradiance: {radiation_w_m2} W/m^2, clear-sky index: {kc})"
            )

        except Exception as e:
            logger.error(f"[TRUST] Weather API error ({e}). Activating mathematical fallback.")
            forecast_cache.update(slot=slot, timestamp=now, source="fallback", kc=None,
                                  yield_percentage=get_fallback_yield())

    return forecast_cache["yield_percentage"]

def get_expected_yield(ts):
    '''
    Expected yield at time ts and the clear-sky index kc (None when the sky is unknown).
    The forecast tells the sky condition (kc), the sun position its evolution: a value
    fetched minutes ago stays accurate while the sun rises or sets.
    '''
    yield_pct = get_current_forecast()

    if forecast_cache.get("source") == "fallback":
        # No weather data: the clear-sky sinusoid shared with the devices, maximum tolerance
        return get_fallback_yield(ts), None

    kc = forecast_cache.get("kc")
    clear_yield = clear_sky_ghi_wm2(solar_elevation_deg(ts)) / 1000.0
    if kc is None:
        # Sun too low when the forecast was taken: assume a clear sky, maximum tolerance
        return max(yield_pct, clear_yield), None
    return kc * clear_yield, kc

def forecast_tolerance(kc):
    '''Relative tolerance on the forecast: tight with a clear sky, wide with clouds or no data.'''
    if kc is None:
        return TOL_CLOUDY
    cloudiness = 1.0 - min(1.0, max(0.0, kc))
    return TOL_CLEAR + (TOL_CLOUDY - TOL_CLEAR) * cloudiness

# --- SOLAR GEOMETRY (physical bound, independent from the weather API) ---
def solar_elevation_deg(ts, latitude=None, longitude=None):
    '''Solar elevation angle in degrees at UTC timestamp ts (NOAA approximation, ~0.5 deg).'''
    lat = math.radians(float(LATITUDE if latitude is None else latitude))
    lon = float(LONGITUDE if longitude is None else longitude)

    utc = time.gmtime(ts)
    hour = utc.tm_hour + utc.tm_min / 60.0 + utc.tm_sec / 3600.0
    gamma = 2.0 * math.pi / 365.0 * (utc.tm_yday - 1 + (hour - 12.0) / 24.0)

    eq_time_min = 229.18 * (0.000075 + 0.001868 * math.cos(gamma) - 0.032077 * math.sin(gamma)
                            - 0.014615 * math.cos(2 * gamma) - 0.040849 * math.sin(2 * gamma))
    declination = (0.006918 - 0.399912 * math.cos(gamma) + 0.070257 * math.sin(gamma)
                   - 0.006758 * math.cos(2 * gamma) + 0.000907 * math.sin(2 * gamma)
                   - 0.002697 * math.cos(3 * gamma) + 0.00148 * math.sin(3 * gamma))

    true_solar_min = hour * 60.0 + eq_time_min + 4.0 * lon
    hour_angle = math.radians(true_solar_min / 4.0 - 180.0)

    cos_zenith = (math.sin(lat) * math.sin(declination)
                  + math.cos(lat) * math.cos(declination) * math.cos(hour_angle))
    return 90.0 - math.degrees(math.acos(max(-1.0, min(1.0, cos_zenith))))

def max_irradiance_wm2(elevation_deg):
    '''
    Upper bound of the irradiance reaching a panel of any orientation under a clear sky
    '''
    if elevation_deg <= NIGHT_ELEVATION_DEG:
        return 0.0

    zenith = min(90.0 - elevation_deg, 96.0)
    air_mass = 1.0 / (math.cos(math.radians(zenith)) + 0.50572 * (96.07995 - zenith) ** -1.6364)
    direct_normal = 1353.0 * 0.7 ** (air_mass ** 0.678)
    diffuse = MAX_DIFFUSE_WM2 * min(1.0, (elevation_deg - NIGHT_ELEVATION_DEG) / 10.0)
    return 1.1 * direct_normal + diffuse

def clear_sky_ghi_wm2(elevation_deg):
    '''Clear-sky global horizontal irradiance, the reference of the sky index'''
    if elevation_deg <= 0:
        return 0.0
    sin_elevation = math.sin(math.radians(elevation_deg))
    return 1098.0 * sin_elevation * math.exp(-0.057 / sin_elevation)

def sky_index_from_yield(yield_pct, ref_ts):
    '''Clear-sky index kc = forecast / clear sky; None near sunrise/sunset'''
    clear = clear_sky_ghi_wm2(solar_elevation_deg(ref_ts))
    if clear < KC_MIN_CLEAR_GHI:
        return None
    return min(KC_MAX, yield_pct * 1000.0 / clear)

def clear_sky_limit(peak_power, ts):
    '''Production of an ideal clear-sky panel at time ts (W)'''
    return peak_power * max_irradiance_wm2(solar_elevation_deg(ts)) / 1000.0

def physical_production_cap(peak_power, ts):
    '''
    Highest production physically possible at time ts (W). Nothing can justify a value
    above it: at night it is the meter noise, during the day the clear-sky limit plus
    the cloud-enhancement margin, never above the nameplate overload
    '''
    cap = clear_sky_limit(peak_power, ts) * CLOUD_ENHANCEMENT_MARGIN
    return max(NIGHT_MAX_WATT, min(cap, peak_power * PEAK_OVERLOAD_RATIO))

# --- FLUX HELPERS ---
def _flux_string(value):
    '''Quote a value as a Flux string literal'''
    escaped = str(value).replace('\\', '\\\\').replace('"', '\\"').replace('${', '\\${')
    return f'"{escaped}"'

def _result_name(record):
    '''Name given with yield(name: ...); it lives in the "result" column, not in _measurement'''
    return record.values.get("result")

def get_node_stats(node_id, window_min=None):
    """
    Retrieves the mean (mu) and standard deviation (sigma) of a node production
    over a short rolling window. Returns (None, None) when the history is too short
    to make a statistical judgement.
    """
    window_min = STATS_WINDOW_MIN if window_min is None else window_min
    query = f'''
        data = from(bucket: {_flux_string(INFLUX_BUCKET)})
            |> range(start: -{int(window_min)}m)
            |> filter(fn: (r) => r["_measurement"] == "production")
            |> filter(fn: (r) => r["node_id"] == {_flux_string(node_id)})
            |> filter(fn: (r) => r["_field"] == "value")
            |> group()

        data |> mean() |> yield(name: "mean")
        data |> stddev() |> yield(name: "stddev")
        data |> count() |> yield(name: "count")
    '''

    try:
        results = {}
        for table in query_api.query(query):
            for record in table.records:
                results[_result_name(record)] = record.get_value()

        count = results.get("count") or 0
        mu = results.get("mean")
        if count < STATS_MIN_SAMPLES or mu is None:
            return None, None
        return mu, results.get("stddev") or 0.0
    except Exception as e:
        logger.error(f"[TRUST] Error on getting stats query for {node_id}: {e}")
        return None, None

def forecast_band(expected_production, peak_power, kc):
    '''
    Allowed deviation from the forecast (W): relative to the expected production with the
    sky-dependent tolerance, never below a small absolute band (low sun, dawn, dusk)
    '''
    return max(expected_production * forecast_tolerance(kc), peak_power * ABS_TOLERANCE_RATIO)

def classify_low_production(production, expected_production, mu, sigma):
    """
    Behavioral analysis of a value below the meteorological band, for monitoring only:
    declaring less energy than expected brings no advantage to the node
    """
    # Almost nothing produced in daylight: fault or heavy shading, worth a maintenance check
    if expected_production > 50 and production < expected_production * MIN_EFFICIENCY_RATIO:
        return "low_production"

    # Not enough history: the value is plausible, nothing to compare against
    if mu is None:
        return "consistent_degradation"

    safe_sigma = sigma if sigma and sigma > 0 else 1.0
    z_score = (production - mu) / safe_sigma

    # A sudden crash indicates an anomaly: the neighbors tell whether it is shared (clouds) or local
    if z_score < -SUDDEN_DROP_Z_SCORE:
        return "sudden_drop"

    # The decline is part of the node's natural deterioration
    return "consistent_degradation"

def check_spatial_anomaly(node_id, time_window=5):
    """
    Check whether the rest of the microgrid is experiencing a drop in generation.
    Returns True if most trusted neighbors dropped (eg. transient shading), False otherwise.
    """
    with closing(sqlite3.connect(DB_PATH)) as conn:
        trusted_neighbors = conn.execute(
            "SELECT node_id FROM devices WHERE node_id != ? AND status = 0 AND trust_score > 60",
            (node_id,)
        ).fetchall()

    # Require a real minimum quorum of trusted neighbors before trusting swarm consensus
    if len(trusted_neighbors) < MIN_SPATIAL_QUORUM:
        return False

    nodes_list = ', '.join(_flux_string(n[0]) for n in trusted_neighbors)
    bucket = _flux_string(INFLUX_BUCKET)

    # Per-node means: comparing each neighbor with itself avoids mixing plants of different size
    query = f'''
        trusted_nodes = [{nodes_list}]
        window = (start, stop) => from(bucket: {bucket})
            |> range(start: start, stop: stop)
            |> filter(fn: (r) => r["_measurement"] == "production")
            |> filter(fn: (r) => contains(value: r["node_id"], set: trusted_nodes))
            |> filter(fn: (r) => r["_field"] == "value")
            |> mean()

        window(start: -1m, stop: now()) |> yield(name: "recent_mean")
        window(start: -{int(time_window)}m, stop: -1m) |> yield(name: "past_mean")
    '''

    try:
        recent, past = {}, {}
        for table in query_api.query(query):
            for record in table.records:
                target = {"recent_mean": recent, "past_mean": past}.get(_result_name(record))
                if target is not None and record.get_value() is not None:
                    target[record.values.get("node_id")] = record.get_value()

        comparable = [n for n in recent if past.get(n, 0) > 0]
        if len(comparable) < MIN_SPATIAL_QUORUM:
            return False

        dropped = sum(1 for n in comparable if recent[n] < past[n] * SPATIAL_DROP_RATIO)
        return dropped * 2 > len(comparable)
    except Exception as e:
        logger.error(f"[TRUST] Error on spatial check query: {e}")
        return False

def _reject(reason):
    TE_MSG_REJECTED.labels(reason=reason).inc()
    TE_VALIDATIONS.labels(result='rejected', reason=reason).inc()

def _apply_violation(cursor, node_id):
    cursor.execute(
        "UPDATE devices SET recent_violations = recent_violations + 1, last_violation_time = CURRENT_TIMESTAMP WHERE node_id = ?",
        (node_id,)
    )

def _clear_observation(cursor, node_id):
    cursor.execute(
        """
        UPDATE devices
        SET observation_state = NULL,
            observation_since = NULL,
            observation_counter = 0
        WHERE node_id = ?
        """,
        (node_id,)
    )

def _roll_energy_window(cursor, node_id, device, window_start, trust):
    '''
    Close the previous 15-minute window when a message opens a new one. The energy declared
    in it is compared with the energy the forecast allows: an excess is the meteorological
    violation (one penalty per window), a clean window earns the trust recovery.
    Returns the trust score after the evaluation
    '''
    previous_start = device["window_start"]
    if previous_start is not None and window_start <= previous_start:
        return trust # Same window (or a late message of the previous one)

    if previous_start is not None:
        declared = device["window_declared_wh"] or 0.0
        allowed = device["window_allowed_wh"] or 0.0

        if declared > allowed + 1e-6:
            new_trust = max(0.0, trust - TRUST_PENALTY)
            _apply_violation(cursor, node_id)
            TE_PENALTY_APPLIED.labels(reason='window_overproduction').inc()
            logger.warning(
                f"[TRUST] Energy above the forecast for {node_id} in the last {WINDOW_SECONDS // 60} minutes: "
                f"{declared:.1f}Wh declared, {allowed:.1f}Wh allowed. Trust: {trust:.1f} -> {new_trust:.1f}"
            )
            trust = new_trust
        elif allowed > 0 and trust < 100.0:
            # SELF HEALING: once per clean window, slower after recent violations
            decay_factor = 0.5 ** min(device["recent_violations"] or 0, 5)
            bonus = TRUST_RECOVERY_BONUS * decay_factor
            logger.debug(f"[TRUST] Recovery for {node_id}: bonus={bonus:.2f} (decay={decay_factor:.3f})")
            trust = min(100.0, trust + bonus)

    cursor.execute(
        "UPDATE devices SET window_start = ?, window_declared_wh = 0, window_allowed_wh = 0 WHERE node_id = ?",
        (window_start, node_id)
    )
    return trust

def _track_local_anomaly(cursor, node_id, observation_state, reason):
    '''
    Monitor a local production anomaly (new shading, fault). It never touches the trust
    score: a persistent anomaly only raises a maintenance alert for the operator.
    '''
    if observation_state is None:
        cursor.execute(
            """
            UPDATE devices
            SET observation_state = ?,
                observation_since = CURRENT_TIMESTAMP,
                observation_counter = 1
            WHERE node_id = ?
            """,
            (LOCAL_ANOMALY_STATE, node_id)
        )
        logger.info(f"[TRUST] Local anomaly ({reason}) for {node_id}; monitoring started.")
        return

    cursor.execute(
        "UPDATE devices SET observation_counter = observation_counter + 1 WHERE node_id = ?",
        (node_id,)
    )
    if observation_state == MAINTENANCE_STATE:
        return

    cursor.execute(
        """
        SELECT observation_counter,
               observation_since < datetime('now', ?)
        FROM devices
        WHERE node_id = ?
        """,
        (f'-{LOCAL_DROP_OBSERVATION_WINDOW_MIN} minutes', node_id)
    )
    obs_counter, window_expired = cursor.fetchone()

    if obs_counter >= LOCAL_DROP_OBSERVATION_LIMIT and window_expired:
        cursor.execute(
            "UPDATE devices SET observation_state = ? WHERE node_id = ?",
            (MAINTENANCE_STATE, node_id)
        )
        TE_MAINTENANCE_ALERTS.labels(reason=reason).inc()
        logger.warning(
            f"[TRUST] Persistent local anomaly ({reason}) for {node_id}: maintenance suggested "
            f"(counter={obs_counter}). Trust and energy credit are not affected."
        )

# --- MQTT MESSAGES HANDLER ---
@TE_PROCESSING_TIME.time()
def on_message(client, userdata, msg):
    '''
    Main validation flow:
    1. Parsing -> 2. Authorization -> 3. Signature -> 4. Anti-replay -> 5. Time
    -> 6. Weather/behavior -> 7. Storage
    '''
    TE_MSG_RECEIVED.inc()

    try:
        raw_text = msg.payload.decode('utf-8')
        payload = json.loads(raw_text)

        # 1. PARSING
        required_keys = ['node_id', 'timestamp', 'production', 'sig', 'seq']
        if not isinstance(payload, dict) or not all(k in payload for k in required_keys) \
                or not isinstance(payload['node_id'], str) or not isinstance(payload['sig'], str):
            logger.warning("[TRUST] Message discarded: incomplete or malformed payload")
            _reject('malformed_payload')
            return

        node_id = payload['node_id']

        try:
            timestamp = int(payload['timestamp'])
        except (TypeError, ValueError) as e:
            logger.error(f"[TRUST] Invalid timestamp for {node_id}: {payload.get('timestamp')!r} ({e})")
            _reject('invalid_timestamp')
            return

        try:
            production = float(payload['production'])
        except (TypeError, ValueError) as e:
            logger.error(f"[TRUST] Invalid production for {node_id}: {payload.get('production')!r} ({e})")
            _reject('invalid_production')
            return

        # NaN would make every comparison below False and slip through the risk matrix
        if not math.isfinite(production) or production < 0:
            logger.warning(f"[TRUST] Non-physical production for {node_id}: {production!r}")
            _reject('invalid_production')
            return

        try:
            incoming_seq = int(payload['seq'])
        except (TypeError, ValueError) as e:
            logger.error(f"[TRUST] Invalid seq for {node_id}: {payload.get('seq')!r} ({e})")
            _reject('invalid_sequence')
            return

        signature = payload.pop('sig')

        with closing(sqlite3.connect(DB_PATH)) as conn:
            cursor = conn.cursor()

            # 2. DATABASE SECURITY GATE (Authorization)
            device = get_device(cursor, node_id)
            if device is None:
                logger.error(f"[TRUST] Message discarded: unknown device {node_id}")
                _reject('unregistered_device')
                return
            if device["status"] == 1:
                logger.debug(f"[TRUST] Message ignored: device {node_id} is on the ban list")
                _reject('banned_device')
                return

            # 3. CRYPTOGRAPHIC SECURITY GATE (Authenticity)
            signed_bytes = verify_integrity(device["public_key"], signature, raw_text, payload)
            if signed_bytes is None:
                logger.warning(f"[TRUST] MESSAGE BLOCKED: invalid signature for node {node_id}")
                _reject('invalid_signature')
                return # Discard immediately without penalty (could be spoofing)

            # 4. ANTI-REPLAY GATE: the signed, persisted sequence is the real replay protection
            last_sequence = device["last_sequence"] or 0
            if incoming_seq <= last_sequence:
                logger.warning(f"[TRUST] Replay/duplicate detected for {node_id}: seq {incoming_seq} <= last {last_sequence}")
                _reject('replay_detected')
                return

            # Energy is credited for the time elapsed since the previous authentic message.
            # Device timestamps are signed and bounded by TIME_WINDOW, so the credited time
            # cannot exceed the real elapsed time by more than one window.
            last_energy_ts = device["last_energy_ts"]
            if last_energy_ts is None:
                interval_s = 0.0
            else:
                interval_s = float(min(max(0, timestamp - last_energy_ts), MAX_ENERGY_INTERVAL_S))

            cursor.execute(
                "UPDATE devices SET last_sequence = ? WHERE node_id = ?",
                (incoming_seq, node_id)
            )
            conn.commit() # Persist the sequence before any slow network call

            current_trust = device["trust_score"]
            peak_power = device["peak_power"] or 3000.0 # Assign 3000W as the default if the database value is null

            # 5. TEMPORAL VALIDATION
            if timestamp < MIN_VALID_TIMESTAMP:
                # The device never synchronized its clock: nothing is credited, no reason to penalize
                logger.warning(f"[TRUST] Unsynchronized clock for {node_id} (timestamp={timestamp})")
                _reject('clock_unsynced')
                return

            current_time = int(time.time())
            time_diff = abs(current_time - timestamp)

            if time_diff > TIME_WINDOW:
                severity_multiplier = min(TEMPORAL_MAX_MULTIPLIER, time_diff / TIME_WINDOW)
                scaled_penalty = TRUST_PENALTY * severity_multiplier
                new_trust = max(0, current_trust - scaled_penalty)
                cursor.execute("UPDATE devices SET trust_score = ? WHERE node_id = ?", (new_trust, node_id))
                _apply_violation(cursor, node_id)
                logger.warning(f"[TRUST] Temporal anomaly ({node_id}): diff {time_diff}s, penalty x{severity_multiplier:.1f}")
                TE_PENALTY_APPLIED.labels(reason='temporal_anomaly').inc()
                if new_trust < TRUST_THRESHOLD_BAN:
                    ban_device(cursor, node_id)
                conn.commit()
                _reject('temporal_anomaly')
                return

            cursor.execute(
                "UPDATE devices SET last_energy_ts = ? WHERE node_id = ?",
                (max(last_energy_ts or 0, timestamp), node_id)
            )

            # 6. PHYSICAL AND METEOROLOGICAL VALIDATION (Ground Truth)
            # Closing the previous 15-minute window applies its meteorological verdict
            current_trust = _roll_energy_window(
                cursor, node_id, device, timestamp - timestamp % WINDOW_SECONDS, current_trust
            )
            new_trust = current_trust

            # The sun position bounds both the forecast and the declared production:
            # no weather can justify a value above the physical cap (at night: meter noise).
            physical_cap = physical_production_cap(peak_power, timestamp)
            expected_yield, kc = get_expected_yield(timestamp)
            expected_production = min(peak_power * expected_yield, clear_sky_limit(peak_power, timestamp))
            band = forecast_band(expected_production, peak_power, kc)

            # History and neighbors are queried only when needed
            if production > physical_cap:
                reason = "above_physical_limit"
            elif abs(production - expected_production) <= band:
                reason = "ok_meteo"
            elif production > expected_production:
                # Plausible instant value (sun between clouds)
                reason = "above_forecast"
            else:
                mu, sigma = get_node_stats(node_id)
                reason = classify_low_production(production, expected_production, mu, sigma)

            # Declaring too much is the only profitable fraud, so it is the only one penalized
            is_valid = reason not in OVERCLAIM_REASONS
            energy_wh = production * interval_s / 3600.0

            if not is_valid:
                new_trust = max(0.0, current_trust - TRUST_PENALTY)
                _apply_violation(cursor, node_id)
                TE_PENALTY_APPLIED.labels(reason=reason).inc()
                logger.warning(
                    f"[TRUST] Spoofing detected for {node_id} ({reason}): {production:.0f}W declared, "
                    f"physical cap {physical_cap:.0f}W. Trust: {current_trust:.1f} -> {new_trust:.1f}"
                )
            else:
                if reason == "consistent_degradation":
                    reason = "ok_degradation"
                elif reason == "sudden_drop":
                    reason = "ok_neigh" if check_spatial_anomaly(node_id) else "local_drop"

                # Energy the forecast allows for this interval, evaluated when the window closes
                allowed_wh = min(expected_production + band, physical_cap) * interval_s / 3600.0
                cursor.execute(
                    """
                    UPDATE devices
                    SET window_declared_wh = window_declared_wh + ?,
                        window_allowed_wh = window_allowed_wh + ?
                    WHERE node_id = ?
                    """,
                    (energy_wh, allowed_wh, node_id)
                )

            if reason in LOCAL_ANOMALY_REASONS:
                _track_local_anomaly(cursor, node_id, device["observation_state"], reason)
            elif is_valid and device["observation_state"] is not None:
                # Back to an expected level (or the history adapted to a new one)
                _clear_observation(cursor, node_id)

            cursor.execute('''UPDATE devices
                            SET trust_score = ?, last_seen = CURRENT_TIMESTAMP
                           WHERE node_id = ?''', (new_trust, node_id))

            # Violations will decay after 24h of good messages
            if is_valid:
                cursor.execute('''
                    UPDATE devices
                    SET recent_violations = MAX(0, recent_violations - 1),
                        last_violation_time = CURRENT_TIMESTAMP
                    WHERE node_id = ? AND last_violation_time < datetime('now', '-1 day')
                ''', (node_id,))

            if new_trust < TRUST_THRESHOLD_BAN:
                ban_device(cursor, node_id)

            conn.commit()

        if new_trust < TRUST_THRESHOLD_BAN:
            _reject('trust_below_threshold')
            return

        if not is_valid:
            _reject(reason)
            return

        # 7. SAVE TO INFLUXDB & BLOCKCHAIN (only validated messages reach this point)
        if energy_wh > 0:
            try:
                transfer_payload = {
                    "from_node": node_id,
                    "to_node": TRANSFER_TO_NODE,
                    "seq": incoming_seq,
                    "power_w": production,
                    "interval_s": interval_s,
                    "wh_amount": energy_wh,
                    "timestamp": timestamp,
                    "sig": signature,
                    "signed_payload": signed_bytes.decode('utf-8'),
                }
                transfer_payload_str = json.dumps(transfer_payload, separators=(',', ':'), ensure_ascii=True)
                publish_result = client.publish(TRANSFERS_TOPIC, transfer_payload_str)
                if publish_result.rc != mqtt.MQTT_ERR_SUCCESS:
                    logger.warning(f"[TRUST] Transfer publish failed for {node_id} (rc={publish_result.rc})")
                else:
                    logger.info(f"[TRUST] Transfer published for {node_id} -> {TRANSFER_TO_NODE} ({energy_wh:.4f}Wh)")
            except Exception as e:
                logger.error(f"[TRUST] Transfer publish error: {e}")

        # Write to InfluxDB
        try:
            point = Point("production") \
                .tag("node_id", node_id) \
                .field("value", production) \
                .field("energy_wh", energy_wh) \
                .field("status", reason) \
                .time(timestamp * 1000000000)
            write_api.write(bucket=INFLUX_BUCKET, record=point)

            TE_MSG_ACCEPTED.inc()
            logger.info(f"[TRUST] Validated data saved for {node_id} (Production: {production}W, Trust: {new_trust})")

        except Exception as e:
            logger.error(f"[TRUST] InfluxDB write error: {e}")

        TE_VALIDATIONS.labels(result='accepted', reason=reason).inc()

    except (json.JSONDecodeError, UnicodeDecodeError):
        logger.error("[TRUST] Message discarded: invalid JSON format")
        _reject('invalid_json')
    except ValueError as e:
        logger.error(f"[TRUST] Unexpected ValueError in on_message: {e}")
        _reject('invalid_types')
    except Exception as e:
        logger.error(f"[TRUST] Unhandled critical error in on_message: {e}")
        _reject('system_error')

# --- CONNECTION CALLBACK ---
def _configure_mqtt_tls(client):
    if not MQTT_USE_TLS:
        logger.warning("[TRUST] MQTT TLS disabled via an environment variable")
        return

    tls_files = {
        "CA": MQTT_TLS_CA_CERT,
        "Client cert": MQTT_TLS_CERT,
        "Client key": MQTT_TLS_KEY,
    }
    missing_files = [f"{name}: {path}" for name, path in tls_files.items() if not os.path.isfile(path)]
    if missing_files:
        raise FileNotFoundError(f"Missing TLS files for MQTT: {', '.join(missing_files)}")

    client.tls_set(
        ca_certs=MQTT_TLS_CA_CERT,
        certfile=MQTT_TLS_CERT,
        keyfile=MQTT_TLS_KEY,
    )
    logger.info(f"[TRUST] MQTT TLS active on port: {MQTT_PORT}")

def _reason_code_to_int(reason_code):
    """Convert Paho-MQTT reason codes to integers whenever possible"""
    if isinstance(reason_code, (int, float)):
        return int(reason_code)
    for attr in ("value", "rc"):
        value = getattr(reason_code, attr, None)
        if isinstance(value, (int, float)):
            return int(value)
    try:
        return int(str(reason_code))
    except (TypeError, ValueError):
        return None

def on_connect(client, userdata, flags, reason_code, properties):
    rc = _reason_code_to_int(reason_code)
    is_success = (rc == 0)
    if hasattr(reason_code, "is_failure"):
        is_success = not bool(reason_code.is_failure)

    if is_success:
        logger.info(f"[TRUST] Successfully connected to MQTT broker ({MQTT_BROKER})")
        client.subscribe(MQTT_TOPIC)
        logger.info(f"[TRUST] Listening on topic: {MQTT_TOPIC}")
    else:
        logger.error(f"[TRUST] MQTT connection failed with code: {reason_code} (rc={rc})")

def on_disconnect(client, userdata, disconnect_flags, reason_code, properties):
    rc = _reason_code_to_int(reason_code)
    is_unexpected = (rc != 0)
    if hasattr(reason_code, "is_failure"):
        is_unexpected = bool(reason_code.is_failure)

    if is_unexpected:
        logger.warning(f"[TRUST] Unexpected disconnection from MQTT broker (code: {reason_code}, rc={rc})")
    else:
        logger.info("[TRUST] MQTT broker disconnection completed")

# --- MAIN LOOP ---
if __name__ == "__main__":
    logger.info("[TRUST] Starting Trust Engine...")

    start_http_server(8000)
    logger.info("[TRUST] Prometheus metrics server started on port 8000")

    mqtt_client = None
    try:
        init_db()

        # Preload weather data into the cache when the container restarts
        get_current_forecast()

        mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        mqtt_client.on_connect = on_connect
        mqtt_client.on_message = on_message
        mqtt_client.on_disconnect = on_disconnect
        _configure_mqtt_tls(mqtt_client)

        logger.info(f"[TRUST] Attempting connection to {MQTT_BROKER}:{MQTT_PORT}...")
        mqtt_client.connect(MQTT_BROKER, MQTT_PORT, 60)

        logger.info("[TRUST] System ready. Validation active.")
        mqtt_client.loop_forever()
    except KeyboardInterrupt:
        logger.info("[TRUST] Shutdown requested by the user...")
        if mqtt_client is not None:
            mqtt_client.disconnect()
    except Exception as e:
        logger.critical(f"[TRUST] Fatal error: {e}")
        raise