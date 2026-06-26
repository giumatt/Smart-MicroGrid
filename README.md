# Smart MicroGrid - Secure IoT Architecture for Decentralized Energy Trading

A secure, resilient, and observable IoT architecture designed for decentralized residential Smart MicroGrids. This project implements a comprehensive defense-in-depth security framework to protect peer-to-peer energy trading networks from sophisticated data injection attacks while maintaining economic fairness and system transparency.

## Overview

Traditional power distribution networks are evolving into Smart Grids, enabling decentralized energy management and local energy communities. Residential MicroGrids allow users to transition from passive consumers to "prosumers" - entities capable of both consuming and producing energy through photovoltaic installations and exchanging surplus energy with neighboring users.

However, this decentralized peer-to-peer architecture introduces critical security challenges. A malicious prosumer has strong economic incentive to manipulate their smart meter readings to fraudulently claim additional energy credits. This project proposes a comprehensive security framework that guarantees the reliability and integrity of energy production data through three synergistic security layers:

1. **Cryptographic Verification**: all data packets are digitally signed using ECDSA-SHA256 and transmitted over secure TLS-encrypted MQTT channels
2. **Meteorological Ground Truth Validation**: a centralized Trust Engine validates readings against real-time weather data, penalizing nodes that report physically impossible production values
3. **Temporal Integrity Validation**: unix epoch timestamps synchronized via NTP ensure replay attacks are neutralized

## Architecture

### System Components

- **Edge Layer**: ESP-32 microcontroller-based smart meters deployed at residential electrical panels
- **Gateway Services**: containerized middleware stack including:
  - Eclipse Mosquitto MQTT broker with mutual TLS
  - Python provisioning service for device certificate enrollment
  - Meteorological Trust Engine for anomaly detection
  - Blockchain service for append-only transaction ledger
  - SQLite database for device metadata and reputation tracking
  - InfluxDB for time-series telemetry storage
- **Observability Stack**: Prometheus metrics collection and Grafana dashboards for operational monitoring
- **Testing Infrastructure**: hardware simulation engine and large-scale swarm simulator

### Security Layers

**Transport Security**
- Mutual TLS (mTLS) with X.509 certificates
- Hardened Eclipse Mosquitto broker configuration
- Certificate-based access control lists
- Hardware-accelerated ECDSA signatures on edge devices

**Application Security**
- Cryptographic signature verification on all telemetry payloads
- Non-repudiation through ECDSA-SHA256 digital signatures
- Temporal validation with NTP synchronization
- Meteorological baseline comparison against Open-Meteo weather API

**Data Integrity**
- Append-only SHA-256 hash-chain blockchain ledger
- Tamper-evident audit trails for financial transactions
- Immutable record preservation for forensic analysis

## Prerequisites

### Hardware Requirements
- Raspberry Pi (or equivalent single-board computer) for gateway deployment
- ESP-32 microcontrollers for smart meter nodes
- Network connectivity (WiFi or Ethernet)

### Software Requirements
- Python 3.8 or higher
- Docker and Docker Compose
- PlatformIO CLI and Arduino/Espressif ESP-IDF
- Git for version control

### System Dependencies
- OpenSSL (for certificate generation)
- Git
- make and build-essentials

## Installation

### 1. Clone the Repository

```bash
git clone https://git.capria.eu/giumatt/Smart-MicroGrid.git
cd Smart-MicroGrid-release
```

### 2. Gateway Setup

#### Deploy Gateway Services
```bash
cd gateway

# Generate certificate authority and cryptographic material
./scripts/setup.sh

# Return to gateway root and start services
docker-compose -f docker-compose.yml up -d

# Verify all services are running
docker-compose ps
```

#### Gateway Services Access
- MQTT Broker: `localhost:8883` (TLS)
- Provisioning Service: `https://localhost:8443` (HTTPS)
- Grafana Dashboard: `http://localhost:3000`
- Prometheus Metrics: `http://localhost:9090`
- InfluxDB: `http://localhost:8086`

### 3. Edge Node (Smart Meter) Firmware

#### Setup PlatformIO Development Environment
```bash
cd firmware

# Install PlatformIO (if not already installed)
pip install platformio

# Install board support
pio boards install espressif32
```

#### Configure Firmware
```bash
# Copy and edit configuration
cp include/config.h.example include/config.h

# Edit config.h with your network SSID, password, and gateway IP
nano include/config.h
```

#### Build and Upload to ESP-32
```bash
# Build for your specific environment (e.g., esp32)
pio run -e esp32-dev

# Upload to connected ESP-32 device
pio run -e esp32-dev -t upload

# Monitor serial output
pio device monitor
```

### 4. Simulation Environment

For testing without physical hardware:

```bash
cd simulation

# Install Python dependencies
pip install -r requirements.txt

# Configure simulation parameters in .env file

# Run large-scale swarm simulation
./start.sh
```

## Usage

### 1. Device Provisioning

Once the gateway is running, new smart meters must be provisioned:

```bash
# On ESP-32, provisioning happens automatically on first boot:
# - Device generates ECDSA key pair
# - Sends Certificate Signing Request (CSR) to gateway
# - Receives signed X.509 certificate
# - Stores certificate locally and begins MQTT communication
```

### 2. Normal Operation

Once provisioned, smart meters automatically:
- Read electrical production metrics from sensors
- Sign payloads with ECDSA-SHA256
- Publish telemetry to MQTT broker every SEND_INTERVAL_MS milliseconds
- Receive trust score feedback from the Trust Engine

### 3. Monitoring and Observability

Access Grafana dashboards to monitor:

```
http://localhost:3000
Default credentials: admin/admin
```

Key dashboards available:
- Overall system health and metrics
- Per-node trust score history
- Blockchain transaction ledger
- Trust Engine rejection rates
- Cryptographic validation performance

### 4. Trust Engine Operation

The centralized Trust Engine continuously:
- Verifies ECDSA signatures on incoming payloads
- Queries Open-Meteo API for real-time solar irradiance data
- Calculates expected production: `P_expected = peak_power * expected_yield`
- Compares reported production against tolerance thresholds:
  - Daylight (P_expected >= 50W): Allow +/- 25% deviation
  - Overcast/Night: Allow +/- 100W absolute deviation
- Updates node reputation scores based on deviation severity
- Bans nodes when trust score falls below threshold

### 5. Testing Attack Scenarios

Deploy the attack firmware to test defense mechanisms:

```bash
cd attack-firmware

# Configure attack parameters in include/config.h
# Set ATTACK_INJECTION_RATE and ATTACK_MULTIPLIER ranges

pio run -e esp32-dev
pio run -e esp32-dev -t upload

# Monitor rejection rate in Grafana dashboard
# System should automatically isolate malicious node
```

## Project Structure

```
Smart-MicroGrid-release/
├── firmware/                    # Production ESP-32 firmware
│   ├── src/                     # C++ source code
│   │   ├── main.cpp
│   │   ├── sensor_manager.cpp
│   │   ├── network_manager.cpp
│   │   ├── security_manager.cpp
│   │   └── provisioning_client.cpp
│   ├── include/                 # Header files
│   ├── test/                    # Unit tests
│   └── platformio.ini
├── attack-firmware/             # Malicious firmware for testing
│   ├── src/                     # Modified C++ with injection logic
│   └── platformio.ini
├── gateway/                     # Python-based gateway services
│   ├── src/
│   │   ├── ca/                  # Certificate authority utilities
│   │   ├── provisioning/        # Flask provisioning service
│   │   ├── trust_engine/        # Meteorological validation engine
│   │   └── blockchain/          # Append-only ledger service
│   ├── grafana/                 # Dashboard configurations
│   ├── prometheus/              # Metrics and alerting rules
│   ├── tests/                   # Python unit tests
│   ├── docker-compose.yml
│   └── requirements.txt
├── simulation/                  # Large-scale testing simulator
│   ├── swarm_simulator.py       # Async swarm simulation engine
│   └── requirements.txt
└── README.md
```

## Testing

### Unit Tests - Edge Firmware

```bash
cd firmware
pio test -e native
```

Tests validate:
- Sensor simulation algorithms
- Cryptographic signing operations
- Provisioning protocol
- NTP time synchronization

## Security Features

### Cryptographic Primitives
- ECDSA with secp256r1 curve for digital signatures
- SHA-256 for hash-chain blockchain
- TLS v1.3 for transport encryption
- X.509 v3 certificates with basic constraints

### Attack Mitigations
- **Spoofing/Identity Attacks**: Mutual TLS with certificate pinning
- **Data Tampering**: ECDSA signatures and meteorological validation
- **Replay Attacks**: NTP-synchronized timestamp validation
- **Information Disclosure**: TLS v1.3 end-to-end encryption
- **Denial of Service**: Rate-limiting and cryptographic operation optimization
- **Logical Data Injection**: Meteorological Ground Truth baseline comparison

### Trust Engine Algorithm
- Continuous behavioral validation using individual meteorological baselines
- Dynamic reputation system with penalty-driven banishment
- Automatic node isolation at application layer (no ACL rewriting required)
- Self-healing recovery for transient faults

## Configuration Parameters

Key parameters in firmware and gateway can be tuned:

**Firmware (`platformio.ini` or `include/config.h`)**
```
SEND_INTERVAL_MS=5000              # Telemetry publication interval
FORECAST_CACHE_SECONDS=300         # Weather data cache duration
FORECAST_NOISE_STDDEV=0.05         # Simulation noise level
MAX_PROVISIONING_RETRIES=3         # Certificate enrollment attempts
ENABLE_WATCHDOG=1                  # Hardware watchdog timer
```

**Gateway (`gateway/src/trust_engine/trust_engine.py`)**
```
TOLERANCE_PERCENTAGE=0.25          # Daytime tolerance margin
NIGHT_ABSOLUTE_MARGIN=100.0        # Nighttime tolerance in watts
TRUST_PENALTY=10.0                 # Points deducted per violation
TRUST_RECOVERY_BONUS=0.5           # Points recovered per good reading
TRUST_THRESHOLD_BAN=20.0           # Score threshold for banishment
```

## License

This project is provided as-is for educational and research purposes.

## Authors

This project was developed as a Master's thesis in Telecommunication Engineering/Computer Engineering at the University of Calabria, Italy.

**Project Authors:**
- Aurelio Benvenuto
- Francesco Carmelo Capria
- Giuseppe Mattia Greco

**Department:** Computer, Modeling, Electronic and Systems Engineering

**Institution:** University of Calabria, Italy

**Year:** 2025-2026