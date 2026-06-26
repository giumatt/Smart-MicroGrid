#include "network_manager.h"
#include "config.h"
#include "security_manager.h"
#include <WiFi.h>
#include <PubSubClient.h>

#if defined(ALLOW_INSECURE_MQTT) && ALLOW_INSECURE_MQTT == 1
    #include <WiFiClient.h>
    static WiFiClient netClient;
    #define USING_TLS 0
#else
    #include <WiFiClientSecure.h>
    // Broker certificate is issued for DNS names (e.g. mosquitto/gateway),
    // while firmware may connect by IP. Use explicit TLS hostname for verification.
    static const char* MQTT_TLS_SERVER_NAME = "mosquitto";

    class MQTTWiFiClientSecure : public WiFiClientSecure {
    public:
        int connect(const char *host, uint16_t port) {
            IPAddress ip;
            if (host && ip.fromString(host) && MQTT_TLS_SERVER_NAME[0] != '\0' && !_use_insecure) {
                return WiFiClientSecure::connect(ip, port, MQTT_TLS_SERVER_NAME, _CA_cert, _cert, _private_key);
            }
            return WiFiClientSecure::connect(host, port);
        }

        int connect(const char *host, uint16_t port, int32_t timeout) {
            _timeout = timeout;
            return connect(host, port);
        }
    };

    static MQTTWiFiClientSecure netClient;
    #define USING_TLS 1
#endif

static PubSubClient mqttClient(netClient);

static void initTime();
static bool waitForTimeSync(int timeout_sec);

// WiFi & Time Initialization
void initNetwork() {
    Serial.println("[NET] Connecting to Wi-Fi...");

    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 60) {
        delay(500);
        Serial.print(".");
        attempts++;
    }

    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("\n[NET] ERROR: WiFi connection failed!");
        return;
    }

    Serial.println();
    Serial.print("[NET] Wi-Fi Connected. IP: ");
    Serial.println(WiFi.localIP());

    initTime();
}

static void initTime() {
    Serial.println("[NET] Time synchronization (NTP)...");
    configTime(GMT_OFFSET_SEC, DAYLIGHT_OFFSET_SEC, NTP_SERVER);

    if (!waitForTimeSync(10)) {
        Serial.println("[NET] WARNING: Time sync failed. TLS validation may fail.");
    } else {
        struct tm timeinfo;
        getLocalTime(&timeinfo);
        Serial.printf("[NET] Time synchronized:  %02d:%02d:%02d\n",
                      timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
    }
}

static bool waitForTimeSync(int timeout_sec) {
    struct tm timeinfo;
    int retry = 0;
    while (!getLocalTime(&timeinfo) && retry < timeout_sec) {
        delay(1000); retry++; DEBUG_PRINT(".");
    }
    return (retry < timeout_sec);
}

// MQTT Initialization
void initMQTT() {
    Serial.print("[MQTT] Initializing ");

#if USING_TLS
    Serial.println("with TLS (secure mode)...");

    const char* caCert     = getCACert();
    const char* clientCert = getDeviceCert();
    const char* clientKey  = getDeviceKey();

    if (!caCert) {
        Serial.println("[MQTT] ERROR: Missing CA certificate. Provisioning required.");
        return;
    }
    netClient.setCACert(caCert);

    if (isProvisioned() && clientCert && clientKey) {
        netClient.setCertificate(clientCert);
        netClient.setPrivateKey(clientKey);
        Serial.println("[MQTT] mTLS client certificate loaded.");
    } else {
        Serial.println("[MQTT] WARNING: Device not provisioned, mTLS unavailable.");
    }
#else
    Serial.println("WITHOUT TLS (insecure mode) — development only.");
#endif

    mqttClient.setServer(MQTT_BROKER, MQTT_PORT);
    mqttClient.setBufferSize(1024);
    Serial.printf("[MQTT] Broker: %s:%d\n", MQTT_BROKER, MQTT_PORT);

#if USING_TLS
    IPAddress brokerIp;
    if (brokerIp.fromString(MQTT_BROKER) && MQTT_TLS_SERVER_NAME[0] != '\0') {
        Serial.printf("[MQTT] TLS SNI/hostname override: %s\n", MQTT_TLS_SERVER_NAME);
    }
#endif
}

// Connection Maintenance
void maintainLink() {
    if (WiFi.status() != WL_CONNECTED) {
        DEBUG_PRINTLN("[NET] WiFi disconnected. Reconnecting...");
        WiFi.reconnect();
        delay(1000);
        return;
    }

    if (!mqttClient.connected()) {
        Serial.print("[MQTT] Connecting to broker...");
        bool connected = mqttClient.connect(MQTT_CLIENT_ID);
        if (connected) {
            Serial.println("Connected!");
        } else {
            Serial.print("Failed, rc=");
            Serial.print(mqttClient.state());
            Serial.println(". Retrying in 5s...");
#if USING_TLS
            char errbuf[256] = {0};
            int tlsErr = netClient.lastError(errbuf, sizeof(errbuf));
            Serial.printf("[MQTT] TLS lastError code: %d\n", tlsErr);
            if (errbuf[0] != '\0') {
                Serial.printf("[MQTT] TLS lastError text: %s\n", errbuf);
            }
#endif
            delay(5000);
            return;
        }
    }

    mqttClient.loop();
}

// Data Transmission
bool sendData(JsonDocument& doc) {
    if (!mqttClient.connected()) {
        DEBUG_PRINTLN("[MQTT] Cannot send: not connected");
        return false;
    }

    char buffer[1024];
    size_t len = serializeJson(doc, buffer, sizeof(buffer));
    if (len == 0) { DEBUG_PRINTLN("[MQTT] JSON serialization failed"); return false; }

    bool success = mqttClient.publish(MQTT_TOPIC, buffer, len);
    DEBUG_PRINTF("[MQTT] Sent %d bytes to %s: %s\n", len, MQTT_TOPIC, success ? "OK" : "FAIL");
    return success;
}

// Status Check
bool isConnected() { return (WiFi.status() == WL_CONNECTED) && mqttClient.connected(); }