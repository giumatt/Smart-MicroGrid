import json
import os
import logging
import sqlite3
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

    # Install the Solidity compiler
    solcx.install_solc('0.8.0')
    
    # Compile the contract
    logger.info("[WEB3] Compiling Smart Contract...")
    compiled_sol = solcx.compile_files([CONTRACT_SOURCE_PATH], output_values=['abi', 'bin'])
    contract_id, contract_interface = compiled_sol.popitem()
    abi = contract_interface['abi']
    bytecode = contract_interface['bin']

    # Deploy
    logger.info("[WEB3] Deploying EnergyLedger contract...")
    EnergyLedger = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = EnergyLedger.constructor().transact({'from': deployer_account})
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    
    contract_address = tx_receipt.contractAddress
    contract_instance = w3.eth.contract(address=contract_address, abi=abi)
    logger.info(f"[WEB3] Smart Contract deployed at: {contract_address}")


def record_transfer_on_chain(from_node, to_node, wh_amount, timestamp, signature):
    """Call the smart contract function to record the data."""
    try:
        with BC_MINING_TIME.time():
            # It constructs the transaction by calling the ‘recordTransfer’ function of the smart contract
            tx_hash = contract_instance.functions.recordTransfer(
                from_node, to_node, int(wh_amount), int(timestamp), signature
            ).transact({'from': deployer_account})
            
            # Waits for the transaction to be included in a block
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
            
            block_hash = receipt.blockHash.hex()
            block_number = receipt.blockNumber
            
            BC_BLOCKS_MINED.inc()
            logger.info(f"[WEB3] Tx included! Block: {block_number} | Hash: {block_hash[:10]}... | Gas used: {receipt.gasUsed}")
            return block_hash, block_number
            
    except Exception as e:
        logger.error(f"[WEB3] Error while interacting with the smart contract: {e}")
        return None, None
    
def verify_transfer_signature(from_node, signed_payload, signature_hex):
    """
    Verify the original node signature carried inside the downstream transfer
    envelope published by the Trust Engine.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        res = conn.execute("SELECT public_key, status FROM devices WHERE node_id=?", (from_node,)).fetchone()
        conn.close()

        if not res or not res[0]:
            logger.warning(f"[WEB3] Signature check failed: no public key for node {from_node}")
            return False

        public_key_pem, status = res

        if status == 1:
            logger.warning(f"[WEB3] Rejected transfer from banned node {from_node}")
            return False

        if not isinstance(signed_payload, dict):
            logger.warning(f"[WEB3] Invalid signed_payload type for {from_node}")
            return False

        signed_node_id = signed_payload.get("node_id")
        if signed_node_id != from_node:
            logger.warning(f"[WEB3] signed_payload.node_id mismatch: {signed_node_id} != {from_node}")
            return False

        public_key = serialization.load_pem_public_key(public_key_pem.encode())

        payload_str = json.dumps(signed_payload, separators=(',', ':'), ensure_ascii=True)

        public_key.verify(
            bytes.fromhex(signature_hex),
            payload_str.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
        )
        return True

    except Exception as e:
        logger.warning(f"[WEB3] Signature verification failed for {from_node}: {e}")
        return False

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

        from_node = data.get('from_node')
        to_node = data.get('to_node')
        wh_amount = data.get('wh_amount')
        timestamp = data.get('timestamp')
        signature = data.get('sig')
        signed_payload = data.get('signed_payload')

        if not all([from_node, to_node, wh_amount, timestamp, signature]) or signed_payload is None:
            BC_TX_REJECTED.labels(reason='missing_fields').inc()
            return

        declared_node_id = signed_payload.get('node_id')
        if declared_node_id != from_node:
            logger.warning(f"[WEB3] signed_payload.node_id/from_node mismatch: {declared_node_id} != {from_node}")
            BC_TX_REJECTED.labels(reason='node_id_mismatch').inc()
            return

        signed_timestamp = signed_payload.get("timestamp")
        if signed_timestamp != timestamp:
            logger.warning(f"[WEB3] signed_payload.timestamp mismatch: {signed_timestamp} != {timestamp}")
            BC_TX_REJECTED.labels(reason='timestamp_mismatch').inc()
            return

        signed_production = signed_payload.get("production")
        if signed_production is None or float(signed_production) != float(wh_amount):
            logger.warning(f"[WEB3] signed_payload.production mismatch: {signed_production} != {wh_amount}")
            BC_TX_REJECTED.labels(reason='amount_mismatch').inc()
            return

        if not verify_transfer_signature(from_node, signed_payload, signature):
            BC_TX_REJECTED.labels(reason='invalid_signature').inc()
            return

        block_hash, block_number = record_transfer_on_chain(from_node, to_node, wh_amount, timestamp, signature)

        if block_hash:
            light_client_payload = json.dumps({
                "blockNumber": block_number,
                "blockHash": block_hash,
                "latestTxNode": from_node
            })
            client.publish(MQTT_OUT_TOPIC, light_client_payload, qos=1)

    except Exception as e:
        logger.error(f"[MQTT] Errore in on_message: {e}")

def _configure_mqtt_tls(client):
    if MQTT_USE_TLS:
        client.tls_set(ca_certs=MQTT_TLS_CA_CERT, certfile=MQTT_TLS_CERT, keyfile=MQTT_TLS_KEY)

if __name__ == "__main__":
    logger.info("Launch of the Web3 Relayer for Smart MicroGrid")
    
    # 1. Init Metrics
    start_http_server(METRICS_PORT)
    
    # 2. Init Blockchain (EVM)
    import time
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