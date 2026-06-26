#include "sensor_manager.h"
#include "config.h"
#include <time.h>
#include <math.h>
#include <ArduinoJson.h>
#include <HTTPClient.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>

// ============================================================================
// Initialization
// ============================================================================
void initSensors() {
#if SIMULATION_MODE
    Serial.println("[SENSOR] Smart Meter SIMULATOR initialized.");
#else
    Serial.println("[SENSOR] Smart Meter initialized (real sensors).");
    // analogReadResolution(12);
    // analogSetAttenuation(ADC_11db);
#endif
}

// ============================================================================
// Data Reading
// ============================================================================
#if SIMULATION_MODE

static float clampFloat(float value, float minValue, float maxValue) {
    if (value < minValue) return minValue;
    if (value > maxValue) return maxValue;
    return value;
}

static float sampleGaussian(float mean, float stddev) {
    const float u1 = (random(1, 10001) / 10001.0f);
    const float u2 = (random(0, 10000) / 10000.0f);
    const float z0 = sqrtf(-2.0f * logf(u1)) * cosf(2.0f * M_PI * u2);
    return mean + z0 * stddev;
}

static float computeFallbackYield(uint32_t nowTs) {
    if (nowTs == 0) {
        return 0.0f;
    }

    time_t nowTime = static_cast<time_t>(nowTs);
    struct tm localTime;
    if (!localtime_r(&nowTime, &localTime)) {
        return 0.0f;
    }

    const float sunrise = FALLBACK_SUNRISE_HOUR;
    const float sunset = FALLBACK_SUNSET_HOUR;
    if (sunset <= sunrise) {
        return 0.0f;
    }

    float hour = localTime.tm_hour + (localTime.tm_min / 60.0f);
    if (hour < sunrise || hour > sunset) {
        return 0.0f;
    }

    float daylightPhase = (hour - sunrise) / (sunset - sunrise);
    float sunFactor = sinf(M_PI * daylightPhase);
    return clampFloat(sunFactor, 0.0f, 1.0f);
}

static bool fetchOpenMeteoYield(float& outYield) {
#if defined(USE_FORECAST_API) && USE_FORECAST_API == 1
    if (WiFi.status() != WL_CONNECTED) {
        return false;
    }

    WiFiClientSecure client;
#if defined(SKIP_CERT_VERIFICATION) && SKIP_CERT_VERIFICATION == 1
    client.setInsecure();
#else
    #ifdef FORECAST_CA_CERT
    client.setCACert(FORECAST_CA_CERT);
    #else
    return false;
    #endif
#endif

    HTTPClient http;
    String url = String(FORECAST_API_URL) +
                 "?latitude=" + String(FORECAST_LATITUDE, 4) +
                 "&longitude=" + String(FORECAST_LONGITUDE, 4) +
                 "&current=shortwave_radiation";

    if (!http.begin(client, url)) {
        return false;
    }
    http.setTimeout(FORECAST_TIMEOUT_MS);

    int httpCode = http.GET();
    if (httpCode != 200) {
        http.end();
        return false;
    }

    String payload = http.getString();
    http.end();

    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, payload);
    if (err) {
        return false;
    }

    float radiation = doc["current"]["shortwave_radiation"] | -1.0f;
    if (radiation < 0.0f) {
        return false;
    }

    outYield = clampFloat(radiation / FALLBACK_PEAK_IRRADIANCE_WM2, 0.0f, 1.0f);
    return true;
#else
    (void)outYield;
    return false;
#endif
}

static float getYieldPercentage(uint32_t nowTs) {
    static bool cacheValid = false;
    static float cachedYield = 0.0f;
    static uint32_t cachedAt = 0;

    if (cacheValid && nowTs >= cachedAt && (nowTs - cachedAt) < FORECAST_CACHE_SECONDS) {
        return cachedYield;
    }

    float yieldPercentage = 0.0f;
    if (fetchOpenMeteoYield(yieldPercentage)) {
        cachedYield = yieldPercentage;
        cachedAt = nowTs;
        cacheValid = true;
        return yieldPercentage;
    }

    yieldPercentage = computeFallbackYield(nowTs);
    cachedYield = yieldPercentage;
    cachedAt = nowTs;
    cacheValid = true;
    return yieldPercentage;
}

EnergyData buildSimulatedEnergyData(float yieldPercentage,
                                    uint32_t timestamp,
                                    float powerNoiseFactor,
                                    float voltageOffset) {
    EnergyData data{};

    // --- Photovoltaic Simulation Logic (aligned with swarm_simulator.py) ---
    const float yieldClamped = clampFloat(yieldPercentage, 0.0f, 1.0f);
    data.power = MAX_NOMINAL_POWER * yieldClamped;

    // --- Adding Variability (for Trust Model sigma calculation) ---
    data.power *= (1.0f + powerNoiseFactor);
    if (data.power < 0.0f) data.power = 0.0f;

    // Voltage Simulation:  230V with grid fluctuations
    data.voltage = 230.0 + voltageOffset;

    // Current Calculation: I = P / V
    data.current = (data.power > 0) ? (data.power / data.voltage) : 0.0;

    data.timestamp = timestamp;
    return data;
}

EnergyData readSimulatedData() {
    struct tm timeinfo;

    // Retrieve synchronized time via NTP
    if (!getLocalTime(&timeinfo)) {
        DEBUG_PRINTLN("[SENSOR] Warning: time not available.");
        return buildSimulatedEnergyData(0.0f, 0, 0.0f, 0.0f);
    }

    uint32_t nowTs = static_cast<uint32_t>(time(NULL));
    float yieldPercentage = getYieldPercentage(nowTs);

    //######################### ATTACK #########################
    // Occasionally inject a small erroneous daily gain (attack simulation).
    // Default: every ATTACK_INJECTION_RATE sends apply a small multiplier.
#if defined(ATTACK_INJECTION_RATE) && ATTACK_INJECTION_RATE > 0
    static uint32_t attackSendCounter = 0;
    if (++attackSendCounter % ATTACK_INJECTION_RATE == 0) {
        int r = random(0, 10001);
        float frac = r / 10000.0f;
        float mult = ATTACK_MULTIPLIER_MIN + frac * (ATTACK_MULTIPLIER_MAX - ATTACK_MULTIPLIER_MIN);
        yieldPercentage *= mult;
        yieldPercentage = clampFloat(yieldPercentage, 0.0f, 2.0f);
        DEBUG_PRINTF("[SENSOR] Injected wrong daily gain: x%.3f -> yield %.3f\n", mult, yieldPercentage);
    }
#endif
    float powerNoiseFactor = sampleGaussian(0.0f, FORECAST_NOISE_STDDEV);
    float voltageOffset = (random(-10, 11) / 10.0);

    return buildSimulatedEnergyData(yieldPercentage, nowTs, powerNoiseFactor, voltageOffset);
}

#else  // Real sensor mode

EnergyData readRealData() {
    EnergyData data;

    data.voltage = 230.0;
    data.current = 0.0;
    data.power = 0.0;
    data.timestamp = (uint32_t)time(NULL);

    Serial.println("[SENSOR] WARNING: Real sensor reading not implemented!");

    return data;
}

#endif

// Wrapper function that selects the right implementation
EnergyData readSensorData() {
#if SIMULATION_MODE
    return readSimulatedData();
#else
    return readRealData();
#endif
}