#include <Arduino.h>
#include <ArduinoJson.h>
#include "config.h"
#include "security_manager.h"
#include "network_manager.h"
#include "sensor_manager.h"
#include "provisioning_client.h"

// ============================================================================
/**
 * Provisioning retry policy
 * - For 4xx errors: likely client/payload issue -> slow retry
 * - For other failures: normal retry
 */
// ============================================================================
#ifndef PROVISIONING_RETRY_DELAY_MS
    #define PROVISIONING_RETRY_DELAY_MS 5000UL
#endif

#ifndef PROVISIONING_4XX_SLOW_RETRY_DELAY_MS
    #define PROVISIONING_4XX_SLOW_RETRY_DELAY_MS (5UL * 60UL * 1000UL) // 5 minutes
#endif

// ============================================================================
// Configuration
// ============================================================================
// SEND_INTERVAL_MS is defined in platformio.ini or config.h
static const unsigned long SEND_INTERVAL = SEND_INTERVAL_MS;
static unsigned long lastSendTime = 0;

// ============================================================================
// Watchdog (Production only)
// ============================================================================
#if defined(ENABLE_WATCHDOG) && ENABLE_WATCHDOG == 1
    #include "esp_task_wdt.h"
    #define WDT_TIMEOUT (WATCHDOG_TIMEOUT_MS / 1000)
#endif

// ============================================================================
// Setup
// ============================================================================
#ifndef UNIT_TEST
void setup() {
    // 1. Serial Monitor Initialization
    Serial.begin(115200);
    delay(1000);

    Serial.println();
    Serial.println("================================================");
    Serial.println("   Smart MicroGrid Project");
    Serial.println("================================================");

#if defined(DEBUG_MODE) && DEBUG_MODE == 1
    Serial.println("   Mode:  DEVELOPMENT (Debug enabled)");
#else
    Serial.println("   Mode: PRODUCTION (Hardened)");
#endif

    Serial.println("================================================");
    Serial.println();

    // 2. Security Initialization (ECDSA Key Generation/Loading)
    initSecurity();

    // 3. Network Initialization (Wi-Fi + NTP)
    initNetwork();

    // 4. Provisioning Check
    if (!isProvisioned()) {
        Serial.println("[SYSTEM] Device not provisioned. Starting enrollment...");

#if defined(MAX_PROVISIONING_RETRIES)
        int retries = MAX_PROVISIONING_RETRIES;
#else
        int retries = 3;
#endif

        while (!isProvisioned() && retries > 0) {
            Serial.printf("[SYSTEM] Provisioning attempt (retries left: %d)\n", retries);

            if (performProvisioning(MQTT_CLIENT_ID)) {
                Serial.println("[SYSTEM] Enrollment successful!");
                break;
            }

            // Decide retry delay based on the last HTTP code printed by provisioning_client
            // The provisioning client prints: [PROV] RESULT_HTTP_CODE=<n>
            // If code is 4xx, slow retry.
            //
            // NOTE: We also support a direct accessor if present.
            int lastCode = -1;
#if defined(__has_include)
    #if __has_include("provisioning_client.h")
        // If provisioning_client exposes getLastProvisioningHttpCode(), use it.
        // (Safe even if not declared? It must be declared in header to compile.)
    #endif
#endif

            // If you add the prototype `int getLastProvisioningHttpCode();` to the header,
            // uncomment the following line:
            lastCode = getLastProvisioningHttpCode();

            retries--;

            if (retries > 0) {
                unsigned long delayMs = PROVISIONING_RETRY_DELAY_MS;

                if (lastCode >= 400 && lastCode <= 499) {
                    delayMs = PROVISIONING_4XX_SLOW_RETRY_DELAY_MS;
                    Serial.printf("[SYSTEM] Provisioning failed with 4xx (%d). Slow-retrying in %lu ms...\n",
                                  lastCode, delayMs);
                } else {
                    Serial.printf("[SYSTEM] Provisioning failed. Retrying in %lu ms...\n", delayMs);
                }

                delay(delayMs);
            }
        }

        if (!isProvisioned()) {
#if defined(SKIP_CERT_VERIFICATION) && SKIP_CERT_VERIFICATION == 1
            Serial.println("[SYSTEM] WARNING:  Provisioning failed but continuing (dev mode)");
#else
            Serial.println("[SYSTEM] CRITICAL: Provisioning failed!  Cannot continue.");
            Serial.println("[SYSTEM] Entering error state.  Reset to retry.");
            while (1) {
                delay(10000);
            }
#endif
        }
    } else {
        Serial.println("[SYSTEM] Device already provisioned.");
    }

    // 5. MQTT Initialization
    initMQTT();

    // 6. Sensor Initialization
    initSensors();

    // 7. Ready
    Serial.println();
    Serial.printf("[SYSTEM] Setup complete.  Sending data every %lu ms\n", SEND_INTERVAL);
    Serial.println("------------------------------------------------");
}
#endif  // UNIT_TEST

// ============================================================================
// Main Loop
// ============================================================================
#ifndef UNIT_TEST
void loop() {
    // Feed watchdog (Production only)
#if defined(ENABLE_WATCHDOG) && ENABLE_WATCHDOG == 1
    esp_task_wdt_reset();
#endif

    // Maintain network connections
    maintainLink();

    unsigned long currentMillis = millis();

    // Sampling and transmission cycle
    if (currentMillis - lastSendTime >= SEND_INTERVAL) {
        lastSendTime = currentMillis;

        if (isConnected()) {
            // A. Read sensor data (simulated or real based on SIMULATION_MODE)
            EnergyData data = readSensorData();

            // B.  Validate timestamp (Production only)
#if defined(REQUIRE_VALID_TIMESTAMP) && REQUIRE_VALID_TIMESTAMP == 1
            if (data.timestamp == 0 || data.timestamp < 1600000000) {
                Serial.println("[ERR] Invalid timestamp.  Skipping transmission.");
                return;
            }
#endif

            // C.  Create JSON document
            JsonDocument doc;
            doc["node_id"] = MQTT_CLIENT_ID;
            doc["timestamp"] = data.timestamp;
            doc["seq"] = getNextSequence();
            doc["production"]  = serialized(String(data.power, 2));    // raw number with 2 decimals

            // D. Digital Signature (Integrity & Non-Repudiation)
            String payload;
            serializeJson(doc, payload);
            String signature = signMessage(payload);

            if (signature.isEmpty()) {
                Serial.println("[ERR] Signature failed. Skipping transmission.");
                return;
            }

            // Add signature to final packet
            doc["sig"] = signature;

            // E.  Transmit via MQTT
            if (sendData(doc)) {
                Serial.printf("[TX] P=%.1fW V=%.1fV | sig=%s.. .\n",
                              data.power, data.voltage,
                              signature.substring(0, 8).c_str());
            } else {
                Serial.println("[ERR] Transmission failed.");
            }

        } else {
            DEBUG_PRINTLN("[WARN] Connection not ready. Waiting...");
        }
    }

    // Small delay to prevent tight looping
    delay(10);
}
#endif  // UNIT_TEST