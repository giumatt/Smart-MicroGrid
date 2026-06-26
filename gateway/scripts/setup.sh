#!/bin/bash
# Setup script to initialize the Smart MicroGrid Gateway
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GATEWAY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CERTS_DIR="$GATEWAY_DIR/certs"
CA_DIR="$GATEWAY_DIR/src/ca"

if [ -t 1 ]; then
    C_RESET="\033[0m"
    C_SETUP="\033[1;36m"
    C_SUCCESS="\033[1;32m"
    C_WARN="\033[1;33m"
    C_ERROR="\033[1;31m"
else
    C_RESET=""
    C_SETUP=""
    C_SUCCESS=""
    C_WARN=""
    C_ERROR=""
fi

setup_msg() {
    echo -e "${C_SETUP}[SETUP]${C_RESET} $*"
}

success_msg() {
    echo -e "${C_SUCCESS}[SETUP]${C_RESET} $*"
}

warn_msg() {
    echo -e "${C_WARN}[WARNING]${C_RESET} $*"
}

error_msg() {
    echo -e "${C_ERROR}[ERROR]${C_RESET} $*"
}

merge_csv() {
    echo "${1:-},${2:-}" | tr ',' '\n' | awk 'NF' | sort -u | paste -sd, -
}

detect_local_ips_csv() {
    {
        command -v ipconfig >/dev/null && ipconfig getifaddr en0 2>/dev/null || true
        command -v ipconfig >/dev/null && ipconfig getifaddr en1 2>/dev/null || true
        command -v ifconfig >/dev/null && ifconfig 2>/dev/null | awk '/inet / && $2 != "127.0.0.1" {print $2}' || true
        command -v hostname >/dev/null && hostname -I 2>/dev/null | tr ' ' '\n' | grep -v '127.0.0.1' || true
    } | awk 'NF' | sort -u | paste -sd, -
}

detect_local_mdns_name() {
    command -v scutil >/dev/null && scutil --get LocalHostName 2>/dev/null | sed 's/$/.local/' || true
}

load_env_if_present() {
    if [ -f "$GATEWAY_DIR/.env" ]; then
        set -a
        . "$GATEWAY_DIR/.env"
        set +a
    fi
}

choose_python() {
    if [ -x "$GATEWAY_DIR/.venv/bin/python" ]; then
        echo "$GATEWAY_DIR/.venv/bin/python"
    else
        command -v python3
    fi
}

run_generator() {
    local cert_name="$1"
    local script_name="$2"
    local reuse_if_exists="$3"

    if [ "$reuse_if_exists" = "true" ] && [ -f "$CERTS_DIR/$cert_name.key" ] && [ -f "$CERTS_DIR/$cert_name.crt" ]; then
        setup_msg "Existing $cert_name cert found, reusing current cert"
        return 0
    fi

    setup_msg "Generating $cert_name certificate..."
    "$PYTHON_BIN" "$script_name"

    if [ ! -f "$CERTS_DIR/$cert_name.key" ] || [ ! -f "$CERTS_DIR/$cert_name.crt" ]; then
        error_msg "$cert_name certificate generation failed!"
        exit 1
    fi

    success_msg "$cert_name certificate generated successfully"
}

load_env_if_present

AUTO_IPS="$(detect_local_ips_csv)"
AUTO_DNS="$(detect_local_mdns_name)"

if [ -n "$AUTO_IPS" ]; then
    PROVISIONER_CERT_IPS="$(merge_csv "${PROVISIONER_CERT_IPS:-}" "$AUTO_IPS")"
    BROKER_CERT_IPS="$(merge_csv "${BROKER_CERT_IPS:-}" "$AUTO_IPS")"
fi

if [ -n "$AUTO_DNS" ]; then
    PROVISIONER_CERT_DNS="$(merge_csv "${PROVISIONER_CERT_DNS:-}" "$AUTO_DNS")"
    BROKER_CERT_DNS="$(merge_csv "${BROKER_CERT_DNS:-}" "$AUTO_DNS")"
fi

setup_msg "Provisioner SAN DNS: ${PROVISIONER_CERT_DNS:-<none>}"
setup_msg "Provisioner SAN IPs: ${PROVISIONER_CERT_IPS:-<none>}"
setup_msg "Broker SAN DNS: ${BROKER_CERT_DNS:-<none>}"
setup_msg "Broker SAN IPs: ${BROKER_CERT_IPS:-<none>}"

PYTHON_BIN="$(choose_python)"

mkdir -p "$CERTS_DIR"
cd "$CA_DIR"

export CERTS_PATH="$CERTS_DIR"
export BROKER_CERT_DNS BROKER_CERT_IPS PROVISIONER_CERT_DNS PROVISIONER_CERT_IPS

run_generator "ca" "generate_ca.py" "true"
run_generator "broker" "generate_broker_cert.py" "false"
run_generator "provisioner" "generate_provisioner_cert.py" "false"

if [ "${GENERATE_NODERED_CERT:-false}" = "true" ]; then
    export NODERED_CERT_CN="${NODERED_CERT_CN:-nodered}"
    run_generator "nodered" "generate_nodered_cert.py" "true"
fi

if [ "${GENERATE_BLOCKCHAIN_CERT:-false}" = "true" ]; then
    export BLOCKCHAIN_CERT_CN="${BLOCKCHAIN_CERT_CN:-blockchain}"
    run_generator "blockchain" "generate_blockchain_cert.py" "true"
fi

warn_msg "ACTION REQUIRED: update .env with Provisioner and Broker IPs and DNS names"
success_msg "You can now run: docker compose up --build -d"