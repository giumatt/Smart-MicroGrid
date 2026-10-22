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

// Same sun-position model used by the gateway;
// the honest part of the simulation never reports more than the sun allows
static const float NIGHT_ELEVATION_DEG = -2.0f;
static const float MAX_DIFFUSE_WM2 = 120.0f;

static float solarElevationDeg(uint32_t nowTs) {
    time_t nowTime = static_cast<time_t>(nowTs);
    struct tm utc;
    if (!gmtime_r(&nowTime, &utc)) {
        return -90.0f;
    }

    const float deg = (float)M_PI / 180.0f;
    const float lat = FORECAST_LATITUDE * deg;
    const float hour = utc.tm_hour + utc.tm_min / 60.0f + utc.tm_sec / 3600.0f;
    const float gamma = 2.0f * (float)M_PI / 365.0f * (utc.tm_yday + (hour - 12.0f) / 24.0f);

    const float eqTimeMin = 229.18f * (0.000075f + 0.001868f * cosf(gamma) - 0.032077f * sinf(gamma)
                                       - 0.014615f * cosf(2 * gamma) - 0.040849f * sinf(2 * gamma));
    const float declination = 0.006918f - 0.399912f * cosf(gamma) + 0.070257f * sinf(gamma)
                              - 0.006758f * cosf(2 * gamma) + 0.000907f * sinf(2 * gamma)
                              - 0.002697f * cosf(3 * gamma) + 0.00148f * sinf(3 * gamma);

    const float hourAngle = ((hour * 60.0f + eqTimeMin + 4.0f * FORECAST_LONGITUDE) / 4.0f - 180.0f) * deg;
    const float cosZenith = sinf(lat) * sinf(declination) + cosf(lat) * cosf(declination) * cosf(hourAngle);
    return 90.0f - acosf(clampFloat(cosZenith, -1.0f, 1.0f)) / deg;
}

static float physicalYieldLimit(uint32_t nowTs) {
    if (nowTs == 0) {
        return 0.0f;
    }

    const float elevation = solarElevationDeg(nowTs);
    if (elevation <= NIGHT_ELEVATION_DEG) {
        return 0.0f;
    }

    // Clear-sky behavior
    const float zenith = fminf(90.0f - elevation, 96.0f);
    const float airMass = 1.0f / (cosf(zenith * (float)M_PI / 180.0f)
                                  + 0.50572f * powf(96.07995f - zenith, -1.6364f));
    const float directNormal = 1353.0f * powf(0.7f, powf(airMass, 0.678f));
    const float diffuse = MAX_DIFFUSE_WM2 * fminf(1.0f, (elevation - NIGHT_ELEVATION_DEG) / 10.0f);
    return (1.1f * directNormal + diffuse) / 1000.0f;
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

// Open-Meteo current data changes every 15 minutes
static const uint32_t FORECAST_SLOT_SECONDS = 900;
static const float KC_MIN_CLEAR_GHI = 50.0f;
static const float KC_MAX = 1.2f;

// Clear-sky global horizontal irradiance (Haurwitz model), same as the trust engine
static float clearSkyGhi(float elevationDeg) {
    if (elevationDeg <= 0.0f) {
        return 0.0f;
    }
    const float sinElevation = sinf(elevationDeg * (float)M_PI / 180.0f);
    return 1098.0f * sinElevation * expf(-0.057f / sinElevation);
}

static float getYieldPercentage(uint32_t nowTs) {
    static bool cacheValid = false;
    static bool fromApi = false;
    static bool skyKnown = false;
    static float cachedYield = 0.0f;
    static float skyIndex = 0.0f;
    static uint32_t cachedSlot = 0;

    const uint32_t slot = nowTs / FORECAST_SLOT_SECONDS;
    if (!cacheValid || slot != cachedSlot) {
        float yieldPercentage = 0.0f;
        fromApi = fetchOpenMeteoYield(yieldPercentage);
        if (fromApi) {
            // The value is the average of the previous 15 minutes: its reference is mid-slot
            const float clear = clearSkyGhi(solarElevationDeg(nowTs - FORECAST_SLOT_SECONDS / 2));
            skyKnown = (clear >= KC_MIN_CLEAR_GHI);
            skyIndex = skyKnown ? fminf(KC_MAX, yieldPercentage * 1000.0f / clear) : 0.0f;
            cachedYield = yieldPercentage;
        }
        cachedSlot = slot;
        cacheValid = true;
    }

    if (!fromApi) {
        // Deterministic function of time, identical to the trust engine fallback
        return computeFallbackYield(nowTs);
    }
    if (!skyKnown) {
        // Sun too low at refresh time
        return cachedYield;
    }
    return clampFloat(skyIndex * clearSkyGhi(solarElevationDeg(nowTs)) / 1000.0f, 0.0f, 1.0f);
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
    float yieldPercentage = fminf(getYieldPercentage(nowTs), physicalYieldLimit(nowTs));

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