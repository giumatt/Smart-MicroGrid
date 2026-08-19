#!/usr/bin/env python3

"""
Asynchronous simulator of an ESP32 swarm for Smart MicroGrid.
Key features:
- One asyncio task per device (no threads or multiprocessing).
- HTTPS enrollment with the provisioner using a CSR to obtain a device certificate (Bootstrap Token secured).
- MQTT connection on port 8883 with mTLS for each device.
- Photovoltaic telemetry synchronized with Open-Meteo (or gateway-compatible mathematical fallback).
- Payload signing:
  - HMAC-SHA256 preferred if the backend returns an HMAC key.
  - ECDSA-SHA256 fallback compatible with current firmware.
- Mandatory jitter on every sleep to prevent synchronized bursts.
- Graceful shutdown on SIGINT/SIGTERM.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import inspect
import json
import logging
import math
import os
import random
import signal
import ssl
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import aiohttp
import aiomqtt
from dotenv import load_dotenv
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

LOGGER = logging.getLogger("swarm")

@dataclass(slots=True)
class SimulationConfig:
    """Configuration class holding all parameters for the simulation."""
    enroll_url: str
    enroll_ca_file: Path
    allow_insecure_enroll: bool
    relax_x509_strict_tls: bool
    mqtt_host: str
    mqtt_port: int
    mqtt_topic: str
    mqtt_blocks_topic: str
    publish_interval_seconds: float
    jitter_ratio: float
    reconnect_delay_seconds: float
    initial_stagger_seconds: float
    enrollment_timeout_seconds: float
    enrollment_retry_delay_seconds: float
    forecast_api_url: str
    forecast_latitude: float
    forecast_longitude: float
    forecast_cache_seconds: float
    forecast_timeout_seconds: float
    use_forecast_api: bool
    fallback_sunrise_hour: float
    fallback_sunset_hour: float
    fallback_peak_irradiance_wm2: float
    runtime_dir: Path

@dataclass(slots=True)
class DeviceRuntimeState:
    """Runtime state specific to a single device."""
    # Static parameter to ensure that devices are not identical while maintaining shared weather data.
    nominal_peak_watt: float
    latest_block_hash: str = "0x0000000000000000000000000000000000000000000000000000000000000000"
    latest_block_number: int = 0

@dataclass(slots=True)
class WeatherRuntimeState:
    """Shared runtime state for weather conditions."""
    cached_yield_percentage: float | None = None
    cached_at_monotonic: float = 0.0
    source: str = "fallback"

class SwarmWeatherService:
    """Shared weather data for the entire swarm, with caching and mathematical fallback."""

    def __init__(self, config: SimulationConfig, http_session: aiohttp.ClientSession) -> None:
        self.config = config
        self.http_session = http_session
        self.state = WeatherRuntimeState()
        self._lock = asyncio.Lock()

    async def get_yield_percentage(self, now_ts: int) -> float:
        """Fetch or calculate the current yield percentage based on the cache or an API call."""
        now_monotonic = time.monotonic()
        # Return cached value if it is still valid
        if self._is_cache_fresh(now_monotonic):
            return float(self.state.cached_yield_percentage)

        async with self._lock:
            # Double check within the lock in case another task updated the cache
            now_monotonic = time.monotonic()
            if self._is_cache_fresh(now_monotonic):
                return float(self.state.cached_yield_percentage)

            if self.config.use_forecast_api:
                try:
                    yield_pct = await self._fetch_open_meteo_yield_percentage()
                    self._update_cache(yield_pct, now_monotonic, source="open-meteo")
                    LOGGER.debug("Weather refresh from Open-Meteo: expected_yield=%.3f", yield_pct)
                    return yield_pct
                except Exception as exc:
                    LOGGER.warning("Forecast API unavailable, using mathematical fallback: %s", exc)

            # Use mathematical fallback if the API fails or is disabled
            yield_pct = self._build_gateway_compatible_fallback(now_ts)
            self._update_cache(yield_pct, now_monotonic, source="fallback")
            return yield_pct

    def _is_cache_fresh(self, now_monotonic: float) -> bool:
        """Check if the cached weather data is still within its TTL."""
        if self.state.cached_yield_percentage is None:
            return False
        return (now_monotonic - self.state.cached_at_monotonic) < self.config.forecast_cache_seconds

    def _update_cache(self, yield_pct: float, now_monotonic: float, source: str) -> None:
        """Update the shared cache with a new yield percentage."""
        self.state.cached_yield_percentage = max(0.0, min(1.0, float(yield_pct)))
        self.state.cached_at_monotonic = now_monotonic
        self.state.source = source

    async def _fetch_open_meteo_yield_percentage(self) -> float:
        """Fetch real-time shortwave radiation data from the Open-Meteo API."""
        params = {
            "latitude": self.config.forecast_latitude,
            "longitude": self.config.forecast_longitude,
            "current": "shortwave_radiation",
        }
        async with self.http_session.get(
            self.config.forecast_api_url,
            params=params,
            timeout=aiohttp.ClientTimeout(total=self.config.forecast_timeout_seconds),
        ) as response:
            if response.status >= 400:
                body = await response.text()
                raise RuntimeError(f"HTTP {response.status} from Open-Meteo: {body[:180]}")
            data = await response.json(content_type=None)

        current_data = data.get("current")
        if not isinstance(current_data, dict):
            raise RuntimeError("Open-Meteo response missing 'current' field")

        radiation = current_data.get("shortwave_radiation")
        if not isinstance(radiation, (int, float)):
            raise RuntimeError("Open-Meteo response missing numeric shortwave_radiation")

        return min(1.0, max(0.0, float(radiation)) / self.config.fallback_peak_irradiance_wm2)

    def _build_gateway_compatible_fallback(self, now_ts: int) -> float:
        """Calculate a simulated yield percentage using a mathematical model."""
        # Mathematical fallback identical to the trust engine gateway.
        sunrise = self.config.fallback_sunrise_hour
        sunset = self.config.fallback_sunset_hour
        if sunset <= sunrise:
            return 0.0

        local_time = time.localtime(now_ts)
        hour = local_time.tm_hour + (local_time.tm_min / 60.0)
        
        # Zero production if outside daylight hours
        if hour < sunrise or hour > sunset:
            return 0.0

        # Simulate a sine wave curve for daily sun intensity
        daylight_phase = (hour - sunrise) / (sunset - sunrise)
        sun_factor = max(0.0, math.sin(math.pi * daylight_phase))
        return sun_factor


class SimulatedDevice:
    """Represents a single simulated ESP32 with independent state."""
    def __init__(
        self,
        device_id: str,
        config: SimulationConfig,
        weather_service: SwarmWeatherService,
        stop_event: asyncio.Event,
        http_session: aiohttp.ClientSession,
    ) -> None:
        self.device_id = device_id
        self.config = config
        self.weather_service = weather_service
        self.stop_event = stop_event
        self.http_session = http_session

        self.private_key: ec.EllipticCurvePrivateKey | None = None
        self.device_cert_pem: str | None = None
        self.ca_cert_pem: str | None = None
        self.hmac_key: bytes | None = None
        self.runtime_paths = self._build_runtime_paths()

        self.state = DeviceRuntimeState(
            nominal_peak_watt=random.uniform(2200.0, 3600.0),
        )

    async def run(self) -> None:
        """Main lifecycle loop of the simulated device."""
        # Small initial stagger to avoid opening N connections at the exact same instant.
        await self._sleep_with_jitter(self.config.initial_stagger_seconds)

        while not self.stop_event.is_set():
            try:
                await self._ensure_enrollment()
                await self._telemetry_loop()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                LOGGER.exception("[%s] Unhandled error: %s", self.device_id, exc)
                await self._sleep_with_jitter(self.config.reconnect_delay_seconds)

        LOGGER.info("[%s] Stopped", self.device_id)

    async def _ensure_enrollment(self) -> None:
        """Loop until the device successfully enrolls and obtains credentials."""
        while not self.stop_event.is_set() and not self._is_enrolled():
            try:
                await self._enroll_once()
                LOGGER.info("[%s] Enrollment completed", self.device_id)
                return
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                LOGGER.warning("[%s] Enrollment failed: %s", self.device_id, exc)
                await self._sleep_with_jitter(self.config.enrollment_retry_delay_seconds)

    async def _enroll_once(self) -> None:
        """Perform a single HTTP request to enroll the device with the provisioner."""
        if self.private_key is None:
            self.private_key = ec.generate_private_key(ec.SECP256R1())
        csr_pem = self._build_csr_pem(self.private_key)

        payload = {
            "device_id": self.device_id,
            "csr": csr_pem,
            "peak_power": int(round(self.state.nominal_peak_watt)),
            "bootstrap_token": f"token-{self.device_id}"  # <-- INIEZIONE TOKEN
        }

        request_ssl = self._build_enrollment_ssl_context()

        try:
            async with self.http_session.post(
                self.config.enroll_url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=self.config.enrollment_timeout_seconds),
                ssl=request_ssl,
            ) as response:
                body = await response.text()
                if response.status >= 500:
                    raise RuntimeError(f"gateway 5xx during enrollment: {response.status}")
                if response.status >= 400:
                    raise RuntimeError(f"gateway 4xx during enrollment: {response.status} {body[:180]}")
                data = json.loads(body)
        except asyncio.TimeoutError as exc:
            raise RuntimeError("enrollment timeout") from exc
        except aiohttp.ClientError as exc:
            raise RuntimeError(f"HTTP enrollment error: {exc}") from exc

        certificate = data.get("certificate")
        ca_certificate = data.get("ca_certificate")

        if not isinstance(certificate, str) or not certificate.strip():
            raise RuntimeError("enrollment response missing certificate")
        if not isinstance(ca_certificate, str) or not ca_certificate.strip():
            raise RuntimeError("enrollment response missing ca_certificate")

        self.device_cert_pem = certificate
        self.ca_cert_pem = ca_certificate

        # If the backend also exposes an HMAC key, use HMAC-SHA256.
        hmac_value = data.get("hmac_key")
        if isinstance(hmac_value, str) and hmac_value.strip():
            self.hmac_key = self._normalize_hmac_key(hmac_value)
        else:
            self.hmac_key = None

        self._write_tls_material_to_disk()

    async def _telemetry_loop(self) -> None:
        """Connect to MQTT and continuously publish telemetry data."""
        while not self.stop_event.is_set():
            try:
                async with aiomqtt.Client(**self._build_mqtt_client_kwargs()) as mqtt_client:
                    LOGGER.info("[%s] Connected to MQTT %s:%s", self.device_id, self.config.mqtt_host, self.config.mqtt_port)
                    
                    await mqtt_client.subscribe(self.config.mqtt_blocks_topic)
                    listen_task = asyncio.create_task(self._listen_for_blocks(mqtt_client))
                    
                    try:
                        publish_count = 0
                        seq_counter = 1

                        while not self.stop_event.is_set():
                            base_payload = await self._build_telemetry_payload(seq_counter)
                            signature = self._sign_payload(base_payload)
                            
                            full_payload = {
                                "node_id": base_payload["node_id"],
                                "timestamp": base_payload["timestamp"],
                                "seq": base_payload["seq"],
                                "production": base_payload["production"],
                                "sig": signature,
                            }
                            
                            mqtt_json = json.dumps(full_payload, separators=(",", ":"), ensure_ascii=True)
                            publish_timeout = max(5.0, min(30.0, self.config.publish_interval_seconds))
                            
                            await asyncio.wait_for(
                                mqtt_client.publish(self.config.mqtt_topic, mqtt_json, qos=0, retain=False),
                                timeout=publish_timeout,
                            )

                            publish_count += 1
                            seq_counter += 1

                            if publish_count == 1:
                                LOGGER.info(
                                    "[%s] First telemetry published to %s (production=%.2fW)",
                                    self.device_id,
                                    self.config.mqtt_topic,
                                    float(base_payload["production"]),
                                )
                            LOGGER.info(
                                "[%s] TX topic=%s production=%.2fW sig=%s...",
                                self.device_id,
                                self.config.mqtt_topic,
                                float(base_payload["production"]),
                                signature[:8],
                            )

                            await self._sleep_with_jitter(self.config.publish_interval_seconds)
                    finally:
                        listen_task.cancel()

            except asyncio.CancelledError:
                raise
            except (aiomqtt.MqttError, OSError, ssl.SSLError) as exc:
                LOGGER.warning("[%s] MQTT error/timeout: %s", self.device_id, exc)
                await self._sleep_with_jitter(self.config.reconnect_delay_seconds)

    async def _build_telemetry_payload(self, seq_counter: int) -> dict[str, Any]:
        """Construct the un-signed telemetry payload."""
        now_ts = int(time.time())
        yield_percentage = await self.weather_service.get_yield_percentage(now_ts)

        # Consistent with trust engine: expected_production = peak_power * expected_yield.
        production_watt = self.state.nominal_peak_watt * yield_percentage

        # Slight measurement noise, maintaining alignment with the gateway model.
        noise = random.gauss(0.0, 0.01)
        production_watt *= (1.0 + noise)
        production_watt = max(0.0, production_watt)

        # The firmware sends production with 2 decimals.
        return {
            "node_id": self.device_id,
            "timestamp": now_ts,
            "seq": seq_counter,
            "production": float(f"{production_watt:.2f}"),
        }

    def _sign_payload(self, payload_without_sig: dict[str, Any]) -> str:
        """Sign the payload using either HMAC (if available) or ECDSA."""
        payload_str = json.dumps(payload_without_sig, separators=(",", ":"), ensure_ascii=True)
        payload_bytes = payload_str.encode("utf-8")

        if self.hmac_key is not None:
            return hmac.new(self.hmac_key, payload_bytes, hashlib.sha256).hexdigest()

        if self.private_key is None:
            raise RuntimeError("Private key not initialized")

        # Firmware compatible: ECDSA SHA256, DER output in lowercase hex.
        signature_der = self.private_key.sign(payload_bytes, ec.ECDSA(hashes.SHA256()))
        return signature_der.hex()

    def _build_csr_pem(self, private_key: ec.EllipticCurvePrivateKey) -> str:
        """Generate a Certificate Signing Request (CSR)."""
        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, self.device_id),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SmartMicroGrid"),
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
                ]
            )
        )
        csr = csr_builder.sign(private_key, hashes.SHA256())
        return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")

    def _build_enrollment_ssl_context(self) -> ssl.SSLContext | bool | None:
        """Prepare the SSL context for the initial enrollment request."""
        if self.config.enroll_url.lower().startswith("http://"):
            return None

        ca_file = self.config.enroll_ca_file
        if ca_file.exists():
            context = ssl.create_default_context(cafile=str(ca_file))
            self._maybe_relax_x509_strict(context)
            return context

        if self.config.allow_insecure_enroll:
            LOGGER.warning("[%s] ENROLL CA not found, using insecure TLS for enrollment", self.device_id)
            return False

        raise FileNotFoundError(
            f"Enrollment CA not found in {ca_file}. "
            "Pass --allow-insecure-enroll or configure --enroll-ca-file."
        )

    def _build_mqtt_client_kwargs(self) -> dict[str, Any]:
        """Construct arguments required for the aiomqtt Client connection."""
        if not self._is_enrolled():
            raise RuntimeError("Device not enrolled: missing certificates")

        tls_context = ssl.create_default_context(cafile=str(self.runtime_paths["ca"]))
        self._maybe_relax_x509_strict(tls_context)
        tls_context.load_cert_chain(
            certfile=str(self.runtime_paths["cert"]),
            keyfile=str(self.runtime_paths["key"]),
        )
        tls_context.check_hostname = True

        kwargs: dict[str, Any] = {
            "hostname": self.config.mqtt_host,
            "port": self.config.mqtt_port,
            "keepalive": 60,
        }

        # Compatibility between aiomqtt versions (identifier/client_id).
        client_signature = inspect.signature(aiomqtt.Client)
        if "identifier" in client_signature.parameters:
            kwargs["identifier"] = self.device_id
        elif "client_id" in client_signature.parameters:
            kwargs["client_id"] = self.device_id

        if "tls_context" in client_signature.parameters:
            kwargs["tls_context"] = tls_context
        elif "tls_params" in client_signature.parameters:
            tls_params_cls = getattr(aiomqtt, "TLSParameters", None)
            if tls_params_cls is None:
                raise RuntimeError("aiomqtt does not expose TLSParameters")
            kwargs["tls_params"] = tls_params_cls(
                ca_certs=str(self.runtime_paths["ca"]),
                certfile=str(self.runtime_paths["cert"]),
                keyfile=str(self.runtime_paths["key"]),
                cert_reqs=ssl.CERT_REQUIRED,
            )
        else:
            raise RuntimeError("Unsupported aiomqtt version: missing tls_context/tls_params")

        return kwargs

    def _maybe_relax_x509_strict(self, context: ssl.SSLContext) -> None:
        """Optionally relax strict TLS certificate checking policies."""
        if not self.config.relax_x509_strict_tls:
            return
        strict_flag = getattr(ssl, "VERIFY_X509_STRICT", 0)
        if strict_flag:
            context.verify_flags &= ~strict_flag

    async def _sleep_with_jitter(self, base_seconds: float) -> None:
        """Sleep for a given amount of time plus or minus a randomized jitter."""
        if base_seconds <= 0:
            return
        jitter = base_seconds * self.config.jitter_ratio
        delay = random.uniform(base_seconds - jitter, base_seconds + jitter)
        delay = max(0.05, delay)

        try:
            await asyncio.wait_for(self.stop_event.wait(), timeout=delay)
        except asyncio.TimeoutError:
            return

    def _write_tls_material_to_disk(self) -> None:
        """Persist the generated key and acquired certificates to disk."""
        if self.private_key is None or self.device_cert_pem is None or self.ca_cert_pem is None:
            raise RuntimeError("Incomplete TLS material")

        self.runtime_paths["dir"].mkdir(parents=True, exist_ok=True)
        key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.runtime_paths["key"].write_bytes(key_pem)
        self.runtime_paths["cert"].write_text(self.device_cert_pem, encoding="utf-8")
        self.runtime_paths["ca"].write_text(self.ca_cert_pem, encoding="utf-8")
        os.chmod(self.runtime_paths["key"], 0o600)

    def _build_runtime_paths(self) -> dict[str, Path]:
        """Determine local file paths for storing this device's configuration."""
        safe_id = self.device_id.replace(":", "_")
        device_dir = self.config.runtime_dir / safe_id
        return {
            "dir": device_dir,
            "key": device_dir / "device.key",
            "cert": device_dir / "device.crt",
            "ca": device_dir / "ca.crt",
        }

    def _is_enrolled(self) -> bool:
        """Check if this device has completely finished its enrollment process."""
        return self.private_key is not None and self.device_cert_pem is not None and self.ca_cert_pem is not None

    @staticmethod
    def _normalize_hmac_key(hmac_value: str) -> bytes:
        """Convert an incoming HMAC key string into bytes appropriately."""
        value = hmac_value.strip()
        try:
            return bytes.fromhex(value)
        except ValueError:
            return value.encode("utf-8")
        
    async def _listen_for_blocks(self, mqtt_client: aiomqtt.Client) -> None:
        """Asynchronously listen for new block hashes from the Gateway."""
        try:
            async for message in mqtt_client.messages:
                if str(message.topic) == self.config.mqtt_blocks_topic:
                    payload = json.loads(message.payload.decode())
                    
                    self.state.latest_block_hash = payload.get("blockHash", "")
                    self.state.latest_block_number = payload.get("blockNumber", 0)
                    latest_tx_node = payload.get("latestTxNode", "")
                    
                    LOGGER.debug(
                        "[%s] Blockchain Sync! Blocco #%d | Hash: %s... | Tx di: %s",
                        self.device_id,
                        self.state.latest_block_number,
                        self.state.latest_block_hash[:10],
                        latest_tx_node
                    )
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            LOGGER.warning("[%s] Error receiving block: %s", self.device_id, exc)


def build_device_id(index: int) -> str:
    """Generate a deterministic ID for a simulated device."""
    # Rimosso lo UUID casuale per permettere il pre-seeding deterministico dei token in SQLite.
    return f"SimMeter_{index:04d}"


def seed_simulator_tokens(device_ids: list[str]) -> None:
    """
    Automatically injects the required bootstrap tokens into the Provisioner's SQLite database
    running inside the Docker container. This ensures the simulator can seamlessly enroll
    without Identity Hijacking defenses blocking the nodes.
    """
    LOGGER.info("Seeding bootstrap tokens into the Provisioner database via Docker...")
    
    tokens_data = [(f"token-{did}", did) for did in device_ids]
    
    py_script = (
        "import sqlite3; "
        "conn = sqlite3.connect('/app/data/gateway.db'); "
        "c = conn.cursor(); "
        "c.execute('CREATE TABLE IF NOT EXISTS bootstrap_tokens (token TEXT PRIMARY KEY, node_id TEXT, used INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)'); "
        f"c.executemany('INSERT OR IGNORE INTO bootstrap_tokens (token, node_id) VALUES (?, ?)', {tokens_data}); "
        "conn.commit(); "
        "conn.close();"
    )
    
    try:
        subprocess.run(
            ["docker", "exec", "smg_provisioner", "python", "-c", py_script],
            check=True,
            capture_output=True,
            text=True
        )
        LOGGER.info("Tokens seeded successfully.")
    except subprocess.CalledProcessError as e:
        LOGGER.warning("Could not automatically seed tokens. Docker exec failed: %s", e.stderr.strip())
    except FileNotFoundError:
        LOGGER.warning("Docker CLI not found. Tokens must be manually seeded if running remotely.")
    except Exception as e:
        LOGGER.warning("Failed to run docker exec: %s", e)


def install_signal_handlers(stop_event: asyncio.Event) -> None:
    """Bind OS signals (like Ctrl+C) to trigger the graceful stop event."""
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except (NotImplementedError, RuntimeError):
            pass


async def run_swarm(config: SimulationConfig, device_count: int) -> None:
    """Initialize and run the simulated device swarm."""
    config.runtime_dir.mkdir(parents=True, exist_ok=True)

    stop_event = asyncio.Event()
    install_signal_handlers(stop_event)

    # 1. Building deterministic IDs
    device_ids = [build_device_id(i + 1) for i in range(device_count)]

    # 2. Inserting tokens in SQLite DB
    seed_simulator_tokens(device_ids)

    connector = aiohttp.TCPConnector(limit=0)
    timeout = aiohttp.ClientTimeout(total=config.enrollment_timeout_seconds)
    
    LOGGER.info(
        "Starting simulation: devices=%d enroll=%s mqtt=%s:%d topic=%s interval=%.1fs jitter=%.0f%% weather=%s(%.4f,%.4f)",
        device_count,
        config.enroll_url,
        config.mqtt_host,
        config.mqtt_port,
        config.mqtt_topic,
        config.publish_interval_seconds,
        config.jitter_ratio * 100,
        "open-meteo" if config.use_forecast_api else "fallback",
        config.forecast_latitude,
        config.forecast_longitude,
    )

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        weather_service = SwarmWeatherService(config=config, http_session=session)
        devices = [
            SimulatedDevice(
                device_id=did,
                config=config,
                weather_service=weather_service,
                stop_event=stop_event,
                http_session=session,
            )
            for did in device_ids
        ]

        tasks = [asyncio.create_task(device.run(), name=device.device_id) for device in devices]

        try:
            await stop_event.wait()
        finally:
            stop_event.set()
            LOGGER.info("Shutdown requested, waiting for tasks to terminate...")
            done, pending = await asyncio.wait(tasks, timeout=20.0)
            if pending:
                LOGGER.warning("Tasks did not terminate in time: %d. Forcibly canceling.", len(pending))
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
            await asyncio.gather(*done, return_exceptions=True)


async def async_main() -> None:
    """Setup arguments, configuration, and kick off the simulation."""
    load_dotenv(override=True)

    def env_value(name: str) -> str | None:
        value = os.getenv(name)
        if value is None:
            return None
        stripped = value.strip()
        return stripped if stripped else None

    def pick(name: str, cli_value: Any, caster: Any = str) -> Any:
        if cli_value is not None:
            return cli_value
        value = env_value(name)
        if value is None:
            raise ValueError(f"Missing configuration: set {name} in the .env file or via CLI")
        return caster(value)

    def as_bool(value: str) -> bool:
        return value.lower() in {"1", "true", "yes", "on"}

    parser = argparse.ArgumentParser(description="ESP32 Swarm Simulator for Smart MicroGrid")
    parser.add_argument("--devices", type=int, default=None, help="Number of simulated devices")
    parser.add_argument("--enroll-url", type=str, default=None, help="Enrollment URL")
    parser.add_argument("--enroll-ca-file", type=Path, default=None, help="CA for enrollment TLS")
    parser.add_argument(
        "--allow-insecure-enroll",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable/disable enrollment TLS verify (dev only)",
    )
    parser.add_argument(
        "--strict-x509",
        "--strict-enroll-x509",
        dest="strict_x509",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Enable strict X.509 checks on enrollment and MQTT (can fail with incomplete dev CA/certs)",
    )
    parser.add_argument("--mqtt-host", type=str, default=None, help="MQTT broker host")
    parser.add_argument("--mqtt-port", type=int, default=None, help="MQTT broker port")
    parser.add_argument("--mqtt-topic", type=str, default=None, help="MQTT topic")
    parser.add_argument("--mqtt-blocks-topic", type=str, default=None, help="MQTT blocks topic for SPV sync")
    parser.add_argument("--interval", type=float, default=None, help="Base publish interval in seconds")
    parser.add_argument("--jitter", type=float, default=None, help="Relative jitter (0.10 = +/-10%%)")
    parser.add_argument("--forecast-lat", type=float, default=None, help="Latitude for Open-Meteo")
    parser.add_argument("--forecast-lon", type=float, default=None, help="Longitude for Open-Meteo")
    parser.add_argument("--forecast-cache-seconds", type=float, default=None, help="Shared forecast cache TTL")
    parser.add_argument("--forecast-timeout-seconds", type=float, default=None, help="Open-Meteo request timeout")
    parser.add_argument("--forecast-api-url", type=str, default=None, help="Forecast API endpoint")
    parser.add_argument(
        "--forecast-api",
        action=argparse.BooleanOptionalAction,
        dest="use_forecast_api",
        default=None,
        help="Enable/disable Open-Meteo (if disabled uses mathematical fallback)",
    )
    parser.add_argument("--fallback-sunrise", type=float, default=None, help="Fallback sunrise hour (local decimal)")
    parser.add_argument("--fallback-sunset", type=float, default=None, help="Fallback sunset hour (local decimal)")
    parser.add_argument("--fallback-peak-irradiance", type=float, default=None, help="Fallback peak irradiance (W/m2)")
    parser.add_argument("--runtime-dir", type=Path, default=None, help="TLS/device state runtime directory")
    parser.add_argument("--log-level", type=str, default=None, help="DEBUG, INFO, WARNING, ERROR")

    args = parser.parse_args()

    strict_x509 = args.strict_x509 if args.strict_x509 is not None else as_bool(pick("SWARM_STRICT_X509", None))
    allow_insecure_enroll = (
        args.allow_insecure_enroll
        if args.allow_insecure_enroll is not None
        else as_bool(pick("SWARM_ALLOW_INSECURE_ENROLL", None))
    )
    use_forecast_api = (
        args.use_forecast_api
        if args.use_forecast_api is not None
        else as_bool(pick("SWARM_USE_FORECAST_API", None))
    )
    device_count = pick("SWARM_DEVICES", args.devices, int)
    log_level = pick("SWARM_LOG_LEVEL", args.log_level, str)

    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")

    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )

    config = SimulationConfig(
        enroll_url=pick("SWARM_ENROLL_URL", args.enroll_url, str),
        enroll_ca_file=pick("SWARM_ENROLL_CA_FILE", args.enroll_ca_file, Path),
        allow_insecure_enroll=allow_insecure_enroll,
        relax_x509_strict_tls=not strict_x509,
        mqtt_host=pick("SWARM_MQTT_HOST", args.mqtt_host, str),
        mqtt_port=pick("SWARM_MQTT_PORT", args.mqtt_port, int),
        mqtt_topic=pick("SWARM_MQTT_TOPIC", args.mqtt_topic, str),
        mqtt_blocks_topic=(args.mqtt_blocks_topic or env_value("SWARM_MQTT_BLOCKS_TOPIC") or "microgrid/blocks/latest"),
        publish_interval_seconds=pick("SWARM_INTERVAL_SECONDS", args.interval, float),
        jitter_ratio=pick("SWARM_JITTER_RATIO", args.jitter, float),
        reconnect_delay_seconds=pick("SWARM_RECONNECT_DELAY_SECONDS", None, float),
        initial_stagger_seconds=pick("SWARM_INITIAL_STAGGER_SECONDS", None, float),
        enrollment_timeout_seconds=pick("SWARM_ENROLLMENT_TIMEOUT_SECONDS", None, float),
        enrollment_retry_delay_seconds=pick("SWARM_ENROLLMENT_RETRY_DELAY_SECONDS", None, float),
        forecast_api_url=pick("SWARM_FORECAST_API_URL", args.forecast_api_url, str),
        forecast_latitude=pick("SWARM_FORECAST_LATITUDE", args.forecast_lat, float),
        forecast_longitude=pick("SWARM_FORECAST_LONGITUDE", args.forecast_lon, float),
        forecast_cache_seconds=pick("SWARM_FORECAST_CACHE_SECONDS", args.forecast_cache_seconds, float),
        forecast_timeout_seconds=pick("SWARM_FORECAST_TIMEOUT_SECONDS", args.forecast_timeout_seconds, float),
        use_forecast_api=use_forecast_api,
        fallback_sunrise_hour=pick("SWARM_FALLBACK_SUNRISE_HOUR", args.fallback_sunrise, float),
        fallback_sunset_hour=pick("SWARM_FALLBACK_SUNSET_HOUR", args.fallback_sunset, float),
        fallback_peak_irradiance_wm2=pick("SWARM_FALLBACK_PEAK_IRRADIANCE_WM2", args.fallback_peak_irradiance, float),
        runtime_dir=pick("SWARM_RUNTIME_DIR", args.runtime_dir, Path),
    )

    await run_swarm(config=config, device_count=device_count)

if __name__ == "__main__":
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        LOGGER.info("Interrupted by keyboard")