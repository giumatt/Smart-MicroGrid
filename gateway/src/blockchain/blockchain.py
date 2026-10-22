import json
import math
import os
import logging
import sqlite3
import time
from contextlib import closing

import paho.mqtt.client as mqtt
from web3 import Web3
import solcx
from prometheus_client import start_http_server, Counter, Histogram

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# --- Setup Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Web3Ledger")

# --- CONFIGURATION ---
MQTT_BROKER = os.getenv("MQTT_BROKER", "mosquitto")
MQTT_PORT = int(os.getenv("MQTT_PORT", "8883"))
MQTT_IN_TOPIC = os.getenv("BLOCKCHAIN_MQTT_TOPIC", "microgrid/transfers")
MQTT_OUT_TOPIC = "microgrid/blocks/latest"  # ESP topic

CERTS_PATH = os.getenv("CERTS_PATH", "/app/certs")
MQTT_USE_TLS = os.getenv("BLOCKCHAIN_MQTT_USE_TLS", "true").strip().lower() in {"1", "true", "yes", "on"}
MQTT_TLS_CA_CERT = os.getenv("BLOCKCHAIN_MQTT_TLS_CA_CERT", f"{CERTS_PATH}/ca.crt")
MQTT_TLS_CERT = os.getenv("BLOCKCHAIN_MQTT_TLS_CERT", f"{CERTS_PATH}/blockchain.crt")
MQTT_TLS_KEY = os.getenv("BLOCKCHAIN_MQTT_TLS_KEY", f"{CERTS_PATH}/blockchain.key")
METRICS_PORT = int(os.getenv("METRICS_PORT", "8001"))

DB_PATH = os.getenv("DB_PATH", "/app/data/gateway.db")

# Same cap used by the Trust Engine
MAX_ENERGY_INTERVAL_S = float(os.getenv("MAX_ENERGY_INTERVAL_S", "300"))
# Transfers older than this are refused
MAX_TRANSFER_AGE_S = float(os.getenv("MAX_TRANSFER_AGE_S", "300"))

# --- WEB3 / EVM CONFIGURATION ---
WEB3_PROVIDER_URI = os.getenv("WEB3_PROVIDER_URI", "http://evm_node:8545")
CONTRACT_SOURCE_PATH = "/app/EnergyLedger.sol"

# --- PROMETHEUS METRICS ---
BC_TX_RECEIVED = Counter('bc_transactions_received_total', 'Total MQTT transactions received by the Trust Engine')
BC_BLOCKS_MINED = Counter('bc_blocks_mined_total', 'Transactions Successfully Added to the Smart Contract')
BC_TX_REJECTED = Counter('bc_rejected_total', 'Discarded transactions', ['reason'])
BC_MINING_TIME = Histogram('bc_mining_seconds', 'Interaction latency with the EVM blockchain')

# Global Web3 variables
w3 = None
contract_instance = None
deployer_account = None

# Highest sequence relayed per node (the contract enforces the same rule on-chain)
last_relayed_seq = {}

def init_blockchain():
    """Connects to the EVM node, compiles, and deploys the smart contract."""
    global w3, contract_instance, deployer_account

    logger.info(f"[WEB3] Connection to EVM node: {WEB3_PROVIDER_URI}")
    w3 = Web3(Web3.HTTPProvider(WEB3_PROVIDER_URI))

    if not w3.is_connected():
        raise ConnectionError(f"Unable to connect to the EVM node at {WEB3_PROVIDER_URI}")

    logger.info(f"[WEB3] Connected. Chain ID: {w3.eth.chain_id}")
    deployer_account = w3.eth.accounts[0]
    w3.eth.default_account = deployer_account

    solcx.install_solc('0.8.0')

    logger.info("[WEB3] Compiling Smart Contract...")
    compiled_sol = solcx.compile_files([CONTRACT_SOURCE_PATH], output_values=['abi', 'bin'], solc_version='0.8.0')
    _, contract_interface = compiled_sol.popitem()
    abi = contract_interface['abi']
    bytecode = contract_interface['bin']

    logger.info("[WEB3] Deploying EnergyLedger contract...")
    EnergyLedger = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = EnergyLedger.constructor().transact({'from': deployer_account})
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    contract_address = tx_receipt.contractAddress
    contract_instance = w3.eth.contract(address=contract_address, abi=abi)
    logger.info(f"[WEB3] Smart Contract deployed at: {contract_address}")


def record_transfer_on_chain(from_node, to_node, wh_amount, timestamp, seq, signature):
    """Call the smart contract function to record the data."""
    try:
        with BC_MINING_TIME.time():
            mwh_amount = int(round(wh_amount * 1000))

            tx_hash = contract_instance.functions.recordTransfer(
                from_node, to_node, mwh_amount, int(timestamp), int(seq), signature
            ).transact({'from': deployer_account})

            receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
            if receipt.status != 1:
                logger.error(f"[WEB3] Transaction reverted for {from_node} (seq={seq})")
                return None, None

            block_hash = receipt.blockHash.hex()
            block_number = receipt.blockNumber

            BC_BLOCKS_MINED.inc()
            logger.info(f"[WEB3] Tx included! Block: {block_number} | Hash: {block_hash[:10]}... | Gas used: {receipt.gasUsed}")
            return block_hash, block_number

    except Exception as e:
        logger.error(f"[WEB3] Error while interacting with the smart contract: {e}")
        return None, None

def _signed_bytes(signed_payload):
    """
    The Trust Engine forwards the exact bytes signed by the device as a string.
    """
    if isinstance(signed_payload, str):
        return signed_payload.encode('utf-8')
    if isinstance(signed_payload, dict):
        return json.dumps(signed_payload, separators=(',', ':'), ensure_ascii=True).encode('utf-8')
    return None

def verify_transfer_signature(from_node, signed_bytes, signature_hex):
    """
    Verify the original node signature carried inside the downstream transfer
    envelope published by the Trust Engine.
    """
    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
            res = conn.execute("SELECT public_key, status FROM devices WHERE node_id=?", (from_node,)).fetchone()

        if not res or not res[0]:
            logger.warning(f"[WEB3] Signature check failed: no public key for node {from_node}")
            return False

        public_key_pem, status = res

        if status == 1:
            logger.warning(f"[WEB3] Rejected transfer from banned node {from_node}")
            return False

        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        public_key.verify(
            bytes.fromhex(signature_hex),
            signed_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        return True

    except Exception as e:
        logger.warning(f"[WEB3] Signature verification failed for {from_node}: {e}")
        return False

def validate_transfer(data, now=None):
    """
    Check that the envelope is consistent with the data signed by the device.
    Returns (transfer_dict, None) when valid, (None, rejection_reason) otherwise.
    """
    now = time.time() if now is None else now

    from_node = data.get('from_node')
    to_node = data.get('to_node')
    wh_amount = data.get('wh_amount')
    power_w = data.get('power_w')
    interval_s = data.get('interval_s')
    timestamp = data.get('timestamp')
    seq = data.get('seq')
    signature = data.get('sig')

    # 0 is a legitimate value for the numeric fields, so check for presence explicitly
    if not from_node or not to_node or not signature \
            or any(v is None for v in (wh_amount, power_w, interval_s, timestamp, seq)):
        return None, 'missing_fields'

    signed_bytes = _signed_bytes(data.get('signed_payload'))
    if signed_bytes is None:
        return None, 'missing_fields'

    if any(isinstance(v, bool) or not isinstance(v, int) for v in (timestamp, seq)):
        return None, 'invalid_types'

    try:
        signed = json.loads(signed_bytes)
        wh_amount, power_w, interval_s = float(wh_amount), float(power_w), float(interval_s)
        signed_production = float(signed.get("production"))
    except (TypeError, ValueError, AttributeError):
        return None, 'invalid_types'

    if signed.get("node_id") != from_node:
        logger.warning(f"[WEB3] signed_payload.node_id/from_node mismatch: {signed.get('node_id')} != {from_node}")
        return None, 'node_id_mismatch'

    if signed.get("timestamp") != timestamp:
        logger.warning(f"[WEB3] signed_payload.timestamp mismatch: {signed.get('timestamp')} != {timestamp}")
        return None, 'timestamp_mismatch'

    if signed.get("seq") != seq:
        logger.warning(f"[WEB3] signed_payload.seq mismatch: {signed.get('seq')} != {seq}")
        return None, 'sequence_mismatch'

    if signed_production != power_w:
        logger.warning(f"[WEB3] signed_payload.production mismatch: {signed_production} != {power_w}")
        return None, 'amount_mismatch'

    # Energy is computed by the Trust Engine: it must be the signed power over a bounded interval
    if not all(math.isfinite(v) for v in (wh_amount, power_w, interval_s)) \
            or power_w < 0 or not (0 <= interval_s <= MAX_ENERGY_INTERVAL_S) \
            or not math.isclose(wh_amount, power_w * interval_s / 3600.0, rel_tol=1e-6, abs_tol=1e-9):
        logger.warning(f"[WEB3] Inconsistent energy for {from_node}: {wh_amount}Wh from {power_w}W x {interval_s}s")
        return None, 'energy_mismatch'

    if abs(now - timestamp) > MAX_TRANSFER_AGE_S:
        logger.warning(f"[WEB3] Stale transfer from {from_node} (timestamp={timestamp})")
        return None, 'stale_transfer'

    if seq <= last_relayed_seq.get(from_node, 0):
        logger.warning(f"[WEB3] Replayed transfer from {from_node}: seq {seq}")
        return None, 'replay_detected'

    return {
        "from_node": from_node,
        "to_node": to_node,
        "wh_amount": wh_amount,
        "timestamp": timestamp,
        "seq": seq,
        "signature": signature,
        "signed_bytes": signed_bytes,
    }, None

# --- MQTT CALLBACKS ---
def on_connect(client, userdata, flags, reason_code, properties):
    rc = reason_code if isinstance(reason_code, int) else getattr(reason_code, 'value', 1)
    if rc == 0:
        logger.info(f"[MQTT] Connected to broker {MQTT_BROKER}")
        client.subscribe(MQTT_IN_TOPIC)
    else:
        logger.error(f"[MQTT] Connection failed, code {rc}")

def on_message(client, userdata, msg):
    """Receives validated transfers from the Trust Engine and anchors them on-chain."""
    try:
        BC_TX_RECEIVED.inc()
        data = json.loads(msg.payload.decode('utf-8'))
        if not isinstance(data, dict):
            BC_TX_REJECTED.labels(reason='invalid_types').inc()
            return

        transfer, reason = validate_transfer(data)
        if transfer is None:
            BC_TX_REJECTED.labels(reason=reason).inc()
            return

        if not verify_transfer_signature(transfer["from_node"], transfer["signed_bytes"], transfer["signature"]):
            BC_TX_REJECTED.labels(reason='invalid_signature').inc()
            return

        # Reserve the sequence before the transaction, so a duplicate cannot race it
        last_relayed_seq[transfer["from_node"]] = transfer["seq"]

        block_hash, block_number = record_transfer_on_chain(
            transfer["from_node"], transfer["to_node"], transfer["wh_amount"],
            transfer["timestamp"], transfer["seq"], transfer["signature"]
        )

        if block_hash:
            light_client_payload = json.dumps({
                "blockNumber": block_number,
                "blockHash": block_hash,
                "latestTxNode": transfer["from_node"]
            })
            client.publish(MQTT_OUT_TOPIC, light_client_payload, qos=1)

    except Exception as e:
        logger.error(f"[MQTT] Error in on_message: {e}")

def _configure_mqtt_tls(client):
    if MQTT_USE_TLS:
        client.tls_set(ca_certs=MQTT_TLS_CA_CERT, certfile=MQTT_TLS_CERT, keyfile=MQTT_TLS_KEY)

if __name__ == "__main__":
    logger.info("Launch of the Web3 Relayer for Smart MicroGrid")

    # 1. Init Metrics
    start_http_server(METRICS_PORT)

    # 2. Init Blockchain (EVM)
    while True:
        try:
            init_blockchain()
            break
        except ConnectionError:
            logger.warning("EVM node not ready yet. I'll try again in 5 seconds...")
            time.sleep(5)

    # 3. Init MQTT
    mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    mqtt_client.on_connect = on_connect
    mqtt_client.on_message = on_message
    _configure_mqtt_tls(mqtt_client)

    mqtt_client.connect(MQTT_BROKER, MQTT_PORT, 60)
    mqtt_client.loop_forever()
