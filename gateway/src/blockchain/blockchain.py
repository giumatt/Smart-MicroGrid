import sqlite3
import hashlib
import json
import os
import paho.mqtt.client as mqtt
from datetime import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
import logging

from prometheus_client import start_http_server, Counter, Histogram

# --- Setup Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("BlockchainLedger")

# --- CONFIGURATION ---
DB_PATH = os.getenv("DB_PATH", "/app/data/gateway.db")
MQTT_BROKER = os.getenv("MQTT_BROKER", "mosquitto")
MQTT_PORT = int(os.getenv("MQTT_PORT", "8883"))
MQTT_TOPIC = os.getenv("BLOCKCHAIN_MQTT_TOPIC", os.getenv("MQTT_TOPIC", "microgrid/transfers"))

CERTS_PATH = os.getenv("CERTS_PATH", "/app/certs")
MQTT_USE_TLS = os.getenv("BLOCKCHAIN_MQTT_USE_TLS", os.getenv("MQTT_USE_TLS", "true")).strip().lower() in {"1", "true", "yes", "on"}
MQTT_TLS_CA_CERT = os.getenv("BLOCKCHAIN_MQTT_TLS_CA_CERT", os.getenv("MQTT_TLS_CA_CERT", f"{CERTS_PATH}/ca.crt"))
MQTT_TLS_CERT = os.getenv("BLOCKCHAIN_MQTT_TLS_CERT", os.getenv("MQTT_TLS_CERT", f"{CERTS_PATH}/blockchain.crt"))
MQTT_TLS_KEY = os.getenv("BLOCKCHAIN_MQTT_TLS_KEY", os.getenv("MQTT_TLS_KEY", f"{CERTS_PATH}/blockchain.key"))
METRICS_PORT = int(os.getenv("METRICS_PORT", "8001"))

# --- PROMETHEUS METRICS ---
BC_TX_RECEIVED = Counter('bc_transactions_received_total', 'Totale transazioni MQTT ricevute')
BC_BLOCKS_MINED = Counter('bc_blocks_mined_total', 'Blocchi inseriti con successo nel ledger')
BC_TX_REJECTED = Counter('bc_rejected_total', 'Transazioni scartate', ['reason'])
BC_MINING_TIME = Histogram('bc_mining_seconds', 'Tempo impiegato per hash e scrittura su SQLite')


def init_ledger():
    """Initialize the ledger table and enforce append-only rules."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            
            c.execute('''
                CREATE TABLE IF NOT EXISTS energy_ledger (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    block_hash TEXT UNIQUE NOT NULL,
                    prev_hash TEXT NOT NULL,
                    from_node TEXT NOT NULL,
                    to_node TEXT NOT NULL,
                    wh_amount REAL NOT NULL,
                    timestamp INTEGER NOT NULL,
                    signature TEXT NOT NULL
                )
            ''')
            
            c.execute('''
                CREATE TRIGGER IF NOT EXISTS prevent_update_ledger
                BEFORE UPDATE ON energy_ledger
                BEGIN SELECT RAISE(ABORT, 'Updates not allowed on the energy ledger'); END;
            ''')
            
            c.execute('''
                CREATE TRIGGER IF NOT EXISTS prevent_delete_ledger
                BEFORE DELETE ON energy_ledger
                BEGIN SELECT RAISE(ABORT, 'Deletes not allowed on the energy ledger'); END;
            ''')
            conn.commit()
            logger.info("[BLOCKCHAIN] Ledger initialized and protected as append-only.")
    except Exception as e:
        logger.error(f"[BLOCKCHAIN] Database initialization error: {e}")
        raise

def verify_signature(from_node, payload_str, signature_hex):
    """
    Verify the transaction ECDSA signature.
    Returns True if the signature is valid.
    """
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("SELECT public_key FROM devices WHERE node_id=?", (from_node,))
            res = c.fetchone()
            
        if not res or not res[0]:
            logger.warning(f"[BLOCKCHAIN] Public key not found for sender node: {from_node}")
            return False
            
        public_key = serialization.load_pem_public_key(res[0].encode())
        
        public_key.verify(
            bytes.fromhex(signature_hex),
            payload_str.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception as e:
        logger.error(f"[BLOCKCHAIN] Invalid signature for transaction from {from_node}: {e}")
        return False

def record_transfer(from_node, to_node, wh_amount, timestamp, signature):
    """
    Record a new energy transfer by computing the hash chain.
    For the first transaction, use a zero hash as prev_hash.
    """
    # Use an EXCLUSIVE lock to prevent race conditions if two processes attempt to write.
    # In SQLite, concurrent writes get an automatic DB lock.
    try:
        with BC_MINING_TIME.time():
            with sqlite3.connect(DB_PATH, isolation_level='EXCLUSIVE') as conn:
                c = conn.cursor()
                
                # Fetch the previous block hash
                c.execute("SELECT block_hash FROM energy_ledger ORDER BY id DESC LIMIT 1")
                row = c.fetchone()
                prev_hash = row[0] if row else "0" * 64  # Zero hash for the genesis block
                
                # Compute the new hash (SHA-256(prev_hash + data))
                data_string = f"{prev_hash}{from_node}{to_node}{wh_amount}{timestamp}{signature}"
                block_hash = hashlib.sha256(data_string.encode('utf-8')).hexdigest()
                
                # Insert into the ledger (append-only)
                c.execute('''
                    INSERT INTO energy_ledger
                    (block_hash, prev_hash, from_node, to_node, wh_amount, timestamp, signature)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (block_hash, prev_hash, from_node, to_node, wh_amount, timestamp, signature))
                
                conn.commit()
                BC_BLOCKS_MINED.inc()
                logger.info(f"[BLOCKCHAIN] New block mined: {block_hash[:8]}... for transfer {from_node} -> {to_node} ({wh_amount} Wh)")
                return block_hash

    except sqlite3.Error as e:
        logger.error(f"[BLOCKCHAIN] SQLite error while recording block: {e}")
        return None
    except Exception as e:
        logger.error(f"[BLOCKCHAIN] Generic error while recording block: {e}")
        return None

# --- MQTT CALLBACKS ---

def on_connect(client, userdata, flags, reason_code, properties):
    # Handle reason_code compatibility
    rc = reason_code if isinstance(reason_code, int) else getattr(reason_code, 'value', 1)
    
    if rc == 0:
        logger.info(f"[BLOCKCHAIN] Connected to MQTT broker {MQTT_BROKER}")
        client.subscribe(MQTT_TOPIC)
        logger.info(f"[BLOCKCHAIN] Listening on {MQTT_TOPIC}")
    else:
        logger.error(f"[BLOCKCHAIN] MQTT connection failed with code {rc}")

def on_message(client, userdata, msg):
    """
    Receive MQTT messages, validate them, and add them to the ledger.
    Expected format: {"from_node": "A", "to_node": "B", "wh_amount": 10.5, "timestamp": 123456789, "sig": "..."}
    """
    try:
        BC_TX_RECEIVED.inc()
        payload_str = msg.payload.decode('utf-8')
        data = json.loads(payload_str)
        
        from_node = data.get('from_node')
        to_node = data.get('to_node')
        wh_amount = data.get('wh_amount')
        timestamp = data.get('timestamp')
        signature = data.get('sig')
        signed_payload = data.get('signed_payload')
        
        if from_node is None or to_node is None or wh_amount is None or timestamp is None or signature is None:
            logger.warning("[BLOCKCHAIN] Transaction discarded: missing fields.")
            BC_TX_REJECTED.labels(reason='missing_fields').inc()
            return
            
        if signed_payload is not None and not isinstance(signed_payload, dict):
            logger.warning("[BLOCKCHAIN] Transaction discarded: invalid signed_payload.")
            BC_TX_REJECTED.labels(reason='invalid_payload').inc()
            return
            
        # Rebuild the exact payload for signature verification
        # If present, use signed_payload (original payload signed by the device)
        if signed_payload:
            signed_node = signed_payload.get('node_id')
            if signed_node and signed_node != from_node:
                logger.warning("[BLOCKCHAIN] Transaction discarded: node_id mismatch with from_node.")
                BC_TX_REJECTED.labels(reason='node_mismatch').inc()
                return
            payload_to_verify_str = json.dumps(signed_payload, separators=(',', ':'), ensure_ascii=True)
        else:
            data_to_verify = data.copy()
            data_to_verify.pop('sig', None)
            data_to_verify.pop('signed_payload', None)
            payload_to_verify_str = json.dumps(data_to_verify, separators=(',', ':'), ensure_ascii=True)
        
        # Verify signature (sender authenticity)
        if not verify_signature(from_node, payload_to_verify_str, signature):
            logger.warning(f"[BLOCKCHAIN]   Transaction REJECTED from {from_node}: Invalid signature.")
            BC_TX_REJECTED.labels(reason='invalid_signature').inc()
            return
            
        # Record the transaction in the ledger
        record_transfer(from_node, to_node, float(wh_amount), int(timestamp), signature)
        
    except json.JSONDecodeError:
        logger.error("[BLOCKCHAIN] Transaction discarded: malformed JSON.")
        BC_TX_REJECTED.labels(reason='malformed_json').inc()
    except Exception as e:
        logger.error(f"[BLOCKCHAIN] Error in on_message: {e}")

def _configure_mqtt_tls(client):
    if not MQTT_USE_TLS:
        logger.warning("[BLOCKCHAIN] MQTT TLS disabled via environment variable")
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
    logger.info(f"[BLOCKCHAIN] MQTT TLS enabled on port {MQTT_PORT}")

# --- MAIN ---
if __name__ == "__main__":
    logger.info("="*50)
    logger.info("Starting Smart MicroGrid Local Blockchain Service")
    logger.info("="*50)
    
    # Initialize database
    init_ledger()
    
    # Expose Prometheus metrics
    start_http_server(METRICS_PORT)
    logger.info(f"[BLOCKCHAIN] Metrics exposed on 0.0.0.0:{METRICS_PORT}")

    # Configure and connect MQTT client
    mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    mqtt_client.on_connect = on_connect
    mqtt_client.on_message = on_message
    
    try:
        _configure_mqtt_tls(mqtt_client)
        logger.info(f"[BLOCKCHAIN] Attempting connection to {MQTT_BROKER}:{MQTT_PORT}...")
        mqtt_client.connect(MQTT_BROKER, MQTT_PORT, 60)
        
        # Start main loop
        mqtt_client.loop_forever()
    except KeyboardInterrupt:
        logger.info("[BLOCKCHAIN] Stop requested by user.")
        mqtt_client.disconnect()
    except Exception as e:
        logger.critical(f"[BLOCKCHAIN] Fatal error: {e}")