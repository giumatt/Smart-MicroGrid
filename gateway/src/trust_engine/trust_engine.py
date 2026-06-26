"""
Trust Engine for Smart MicroGrid
Validates telemetry messages through cryptographic, temporal, and meteorological checks.
Manages device trust scores, self-healing, and banning logic.
"""
import json
import sqlite3
import paho.mqtt.client as mqtt
import os
import time
import requests
import math
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import logging

# --- IMPORT PROMETHEUS CLIENT ---
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
TOLERANCE_PERCENTAGE = float(os.getenv("TOLERANCE_PERCENTAGE", "0.25")) # 25% error margin

# Ground Truth Location (Default: Roma)
LATITUDE = os.getenv("LATITUDE", "41.90")
LONGITUDE = os.getenv("LONGITUDE", "12.49")

# --- PROMETHEUS METRICS DEFINITIONS ---
TE_MSG_RECEIVED = Counter('te_messages_received_total', 'Total MQTT telemetry messages received')
TE_MSG_ACCEPTED = Counter('te_messages_accepted_total', 'Messages successfully validated and stored')
TE_MSG_REJECTED = Counter('te_messages_rejected_total', 'Messages rejected during validation', ['reason'])
TE_PENALTY_APPLIED = Counter('te_penalties_applied_total', 'Trust penalties applied to nodes', ['reason'])
TE_PROCESSING_TIME = Histogram('te_processing_seconds', 'Time spent processing an entire message')
TE_CRYPTO_TIME = Histogram('te_crypto_validation_seconds', 'Time spent explicitly in ECDSA verification')
TE_VALIDATIONS = Counter('te_validations_total', 'Validation outcomes for telemetry', ['result', 'reason'])

# --- FORECAST GROUND TRUTH ---
forecast_cache = {
    "timestamp": 0,
    "yield_percentage": 0.0
}

# --- INFLUXDB INITIALIZATION ---
try:
    influx_client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
    write_api = influx_client.write_api(write_options=SYNCHRONOUS)
    logger.info(f"[TRUST] InfluxDB client initialized successfully")
except Exception as e:
    logger.error(f"[TRUST] Failed to initialize InfluxDB client: {e}")
    raise

# --- SQLITE MANAGEMENT ---
def init_db():
    '''Initialize the SQLite database with safe migrations'''
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Main table creation
        c.execute('''CREATE TABLE IF NOT EXISTS devices
                  (node_id TEXT PRIMARY KEY,
                  public_key TEXT NOT NULL,
                  trust_score REAL DEFAULT 100.0,
                  status INTEGER DEFAULT 0,
                  last_seen TIMESTAMP,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

        # Safe migration: add the peak_power column if it does not exist
        try:
            c.execute("ALTER TABLE devices ADD COLUMN peak_power REAL DEFAULT 3000.0")
            logger.info("[TRUST] DB Migration: Added column 'peak_power'.")
        except sqlite3.OperationalError:
            pass # The column already exists
            
        conn.commit()
        conn.close()
        logger.info(f"[TRUST] Database initialized/verified at {DB_PATH}")
    except Exception as e:
        logger.error(f"[TRUST] Database initialization failed: {e}")
        raise

def check_device_status(cursor, node_id):
    '''Check whether the device exists, is active or banned, and retrieve its data'''
    try:
        cursor.execute("SELECT status, trust_score, peak_power FROM devices WHERE node_id = ?", (node_id,))
        row = cursor.fetchone()
        if row is None:
            return None, None, None # Unregistered device
        return row[0], row[1], row[2] # status, trust_score, peak_power
    except Exception as e:
        logger.error(f"[TRUST] Security gate check failed: {e}")
        return None, None, None

def ban_device(cursor, node_id):
    '''Permanently ban a device by setting status = 1 in the DB'''
    try:
        cursor.execute("UPDATE devices SET status = 1 WHERE node_id = ?", (node_id,))
        logger.warning(f"[TRUST] DEVICE BANNED: {node_id} (Trust dropped below {TRUST_THRESHOLD_BAN})")
    except Exception as e:
        logger.error(f"[TRUST] Failed to ban device: {e}")

# --- CRYPTOGRAPHIC VERIFICATION ---
def verify_integrity(data_without_sig, signature_hex, node_id):
    """
    Verify the ECDSA-SHA256 signature of the payload.
    Guarantees message authenticity and integrity.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        res = conn.execute("SELECT public_key FROM devices WHERE node_id=?", (node_id,)).fetchone()
        conn.close()

        if not res or not res[0]:
            logger.warning(f"[TRUST] Cryptographic validation failed: public key not found for {node_id}")
            return False

        # Load the public key (PEM format)
        public_key = serialization.load_pem_public_key(res[0].encode())
        
        # Rebuild the JSON string exactly as it was signed by the ESP32
        payload_str = json.dumps(data_without_sig, separators=(',', ':'), ensure_ascii=True)
        
        # Start the cryptographic timer
        with TE_CRYPTO_TIME.time():
            public_key.verify(
                bytes.fromhex(signature_hex),
                payload_str.encode('utf-8'),
                ec.ECDSA(hashes.SHA256())
            )
        return True
    except Exception as e:
        logger.error(f"[TRUST] Invalid or corrupted signature for {node_id}: {e}")
        return False

def get_fallback_yield():
    '''Emergency mathematical model used if the weather APIs are offline.'''
    now_ts = int(time.time())
    local_time = time.localtime(now_ts)
    hour = local_time.tm_hour + (local_time.tm_min / 60.0)
    
    if hour < 6.0 or hour > 18.0:
        return 0.0 # Night
    
    # Sinusoidal curve from 06:00 to 18:00
    daylight_phase = (hour - 6.0) / 12.0
    sun_factor = math.sin(math.pi * daylight_phase)
    return max(0.0, sun_factor)

def get_current_forecast():
    '''
    Retrieve the current solar irradiance from Open-Meteo.
    Uses a 30-minute cache to avoid rate limiting.
    Returns the expected yield percentage (0.0 - 1.0).
    '''
    global forecast_cache
    now = time.time()
    
    # Refresh the cache every 30 minutes (1800 seconds)
    if now - forecast_cache["timestamp"] > 1800:
        try:
            url = f"https://api.open-meteo.com/v1/forecast?latitude={LATITUDE}&longitude={LONGITUDE}&current=shortwave_radiation"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            radiation_w_m2 = data["current"]["shortwave_radiation"]
            
            # Assume a theoretical maximum irradiance of ~1000 W/m^2
            yield_pct = min(1.0, radiation_w_m2 / 1000.0)
            
            forecast_cache["yield_percentage"] = yield_pct
            forecast_cache["timestamp"] = now
            logger.info(f"[TRUST] Weather forecast updated: estimated yield {yield_pct*100:.1f}% (Irradiance: {radiation_w_m2} W/m^2)")
            
        except Exception as e:
            logger.error(f"[TRUST] Weather API error ({e}). Activating mathematical fallback.")
            forecast_cache["yield_percentage"] = get_fallback_yield()
            forecast_cache["timestamp"] = now 
            
    return forecast_cache["yield_percentage"]

# --- MQTT MESSAGES HANDLER ---
@TE_PROCESSING_TIME.time()
def on_message(client, userdata, msg):
    '''
    Main validation flow:
    1. Parsing -> 2. Signature -> 3. Status -> 4. Time -> 5. Weather -> 6. Storage
    '''
    TE_MSG_RECEIVED.inc()
    
    try:
        payload = json.loads(msg.payload.decode())
        
        # 1. PAYLOAD INTEGRITY CHECK
        required_keys = ['node_id', 'timestamp', 'production', 'sig']
        if not all(k in payload for k in required_keys):
            logger.warning("[TRUST] Message discarded: incomplete or malformed payload")
            TE_MSG_REJECTED.labels(reason='malformed_payload').inc()
            TE_VALIDATIONS.labels(result='rejected', reason='malformed_payload').inc()
            return
        
        node_id = payload['node_id']
        timestamp = payload['timestamp']
        production = float(payload['production'])
        signature = payload.pop('sig') # Extract the signature by removing it from the dict
        signed_payload = payload.copy()
        validation_reason = "ok"
        
        # 2. CRYPTOGRAPHIC SECURITY GATE (Authenticity)
        if not verify_integrity(payload, signature, node_id):
            logger.warning(f"[TRUST] MESSAGE BLOCKED: invalid signature for node {node_id}")
            TE_MSG_REJECTED.labels(reason='invalid_signature').inc()
            TE_VALIDATIONS.labels(result='rejected', reason='invalid_signature').inc()
            return # Discard immediately without penalty (could be spoofing)

        # 3. DATABASE SECURITY GATE (Authorization)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        status, current_trust, peak_power = check_device_status(cursor, node_id)
        
        if status is None:
            logger.error(f"[TRUST] Message discarded: unknown device {node_id}")
            TE_MSG_REJECTED.labels(reason='unregistered_device').inc()
            TE_VALIDATIONS.labels(result='rejected', reason='unregistered_device').inc()
            conn.close()
            return
        if status == 1:
            logger.debug(f"[TRUST] Message ignored: device {node_id} is on the ban list")
            TE_MSG_REJECTED.labels(reason='banned_device').inc()
            TE_VALIDATIONS.labels(result='rejected', reason='banned_device').inc()
            conn.close()
            return
            
        # Assign 3000W as the default if the database value is null
        peak_power = peak_power if peak_power else 3000.0

        # 4. TEMPORAL VALIDATION (Anti-Replay)
        current_time = int(time.time())
        time_diff = abs(current_time - timestamp)
        
        if time_diff > TIME_WINDOW:
            new_trust = max(0, current_trust - TRUST_PENALTY)
            cursor.execute("UPDATE devices SET trust_score = ? WHERE node_id = ?", (new_trust, node_id))
            logger.warning(f"[TRUST] Temporal anomaly ({node_id}): difference {time_diff}s. Trust: {current_trust:.1f} -> {new_trust:.1f}")
            TE_PENALTY_APPLIED.labels(reason='temporal_anomaly').inc()
            
            if new_trust < TRUST_THRESHOLD_BAN: ban_device(cursor, node_id)
            conn.commit(); conn.close()
            TE_MSG_REJECTED.labels(reason='temporal_anomaly').inc()
            TE_VALIDATIONS.labels(result='rejected', reason='temporal_anomaly').inc()
            return

        # 5. METEOROLOGICAL VALIDATION AND SELF-HEALING (Ground Truth)
        expected_yield = get_current_forecast()
        expected_production = peak_power * expected_yield
        
        is_valid = False
        if expected_production < 50:
            # At night or under fully overcast skies, use an absolute watt margin
            error_margin = abs(production - expected_production)
            is_valid = error_margin <= 100.0
        else:
            # During the day, use a percentage margin (e.g. 25%)
            error_margin = abs(production - expected_production) / expected_production
            is_valid = error_margin <= TOLERANCE_PERCENTAGE

        new_trust = current_trust

        if not is_valid:
            # Inconsistent data: penalty
            new_trust = max(0.0, current_trust - TRUST_PENALTY)
            logger.warning(f"[TRUST] Weather anomaly ({node_id}): expected ~{expected_production:.0f}W, got {production:.0f}W. Trust: {current_trust:.1f} -> {new_trust:.1f}")
            TE_PENALTY_APPLIED.labels(reason='meteo_anomaly').inc()
            validation_reason = "meteo_anomaly"
        else:
            # Consistent data: self-healing
            if current_trust < 100.0:
                new_trust = min(100.0, current_trust + TRUST_RECOVERY_BONUS)
                logger.debug(f"[TRUST] Recovery ({node_id}): consistent data. Trust restored: {current_trust:.1f} -> {new_trust:.1f}")

        # Update score and last seen
        cursor.execute('''UPDATE devices 
                          SET trust_score = ?, last_seen = CURRENT_TIMESTAMP 
                          WHERE node_id = ?''', (new_trust, node_id))
        
        if new_trust < TRUST_THRESHOLD_BAN:
            ban_device(cursor, node_id)

        conn.commit()
        conn.close()

        if new_trust < TRUST_THRESHOLD_BAN:
            TE_MSG_REJECTED.labels(reason='trust_below_threshold').inc()
            TE_VALIDATIONS.labels(result='rejected', reason='trust_below_threshold').inc()
            return

        # 6. SAVE TO INFLUXDB & BLOCKCHAIN (only if the node is still healthy)
        if new_trust >= TRUST_THRESHOLD_BAN:
            # Publish to Blockchain Ledger
            try:
                transfer_payload = {
                    "from_node": node_id,
                    "to_node": TRANSFER_TO_NODE,
                    "wh_amount": float(production),
                    "timestamp": int(timestamp),
                    "sig": signature,
                    "signed_payload": signed_payload,
                }
                transfer_payload_str = json.dumps(transfer_payload, separators=(',', ':'), ensure_ascii=True)
                publish_result = client.publish(TRANSFERS_TOPIC, transfer_payload_str)
                if publish_result.rc != mqtt.MQTT_ERR_SUCCESS:
                    logger.warning(f"[TRUST] Transfer publish failed for {node_id} (rc={publish_result.rc})")
                else:
                    logger.info(f"[TRUST] Transfer published for {node_id} -> {TRANSFER_TO_NODE} ({production}W)")
            except Exception as e:
                logger.error(f"[TRUST] Transfer publish error: {e}")
                
            # Write to InfluxDB
            try:
                point = Point("production") \
                    .tag("node_id", node_id) \
                    .field("value", float(production)) \
                    .time(timestamp * 1000000000) 
                write_api.write(bucket=INFLUX_BUCKET, record=point)
                
                TE_MSG_ACCEPTED.inc()
                logger.info(f"[TRUST] Validated data saved for {node_id} (Production: {production}W, Trust: {new_trust})")
                
            except Exception as e:
                logger.error(f"[TRUST] InfluxDB write error: {e}")

            TE_VALIDATIONS.labels(result='accepted', reason=validation_reason).inc()

    except json.JSONDecodeError:
        logger.error(f"[TRUST] Message discarded: invalid JSON format")
        TE_MSG_REJECTED.labels(reason='invalid_json').inc()
        TE_VALIDATIONS.labels(result='rejected', reason='invalid_json').inc()
    except ValueError:
        logger.error(f"[TRUST] Message discarded: incorrect data types in the payload")
        TE_MSG_REJECTED.labels(reason='invalid_types').inc()
        TE_VALIDATIONS.labels(result='rejected', reason='invalid_types').inc()
    except Exception as e:
        logger.error(f"[TRUST] Unhandled critical error in on_message: {e}")
        TE_MSG_REJECTED.labels(reason='system_error').inc()
        TE_VALIDATIONS.labels(result='rejected', reason='system_error').inc()

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
        logger.info(f"[TRUST] MQTT broker disconnection completed")

# --- MAIN LOOP ---
if __name__ == "__main__":
    logger.info("[TRUST] Starting Trust Engine...")
    
    # Start the Prometheus metrics server on port 8000
    start_http_server(8000)
    logger.info("[TRUST] Prometheus metrics server started on port 8000")
    
    try:
        # Initialize the database
        init_db()

        # Preload weather data into the cache when the container restarts
        get_current_forecast()

        # Initialize the MQTT client
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
        mqtt_client.disconnect()
    except Exception as e:
        logger.critical(f"[TRUST] Fatal error: {e}")
        raise