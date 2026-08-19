/**
 * Provisioning Client Module
 * Handles the secure enrollment process for the ESP32 device, 
 * including generating a CSR, connecting to the provisioning server via mTLS/HTTPS,
 * and storing the newly issued certificate and CA.
 */

#include "provisioning_client.h"
#include "security_manager.h"
#include "config.h"
#include <HTTPClient.h>
#include <WiFi.h>
#include <ArduinoJson.h>
#include <time.h>

// Default timeout for HTTP operations (ms)
#define HTTP_TIMEOUT 10000

// 2026-01-01 00:00:00 UTC
#define MIN_VALID_TLS_EPOCH 1767225600

// If the provisioner's certificate has a CN/SAN with a hostname, set it here for the Host header.
// If you use the IP directly and the cert is issued for the IP, leave it empty.
static const char* PROVISIONER_HOST_HEADER = "";  // e.g., "gateway.local"

// If the URL uses an IP but the server certificate uses DNS (CN/SAN), set the TLS name here.
static const char* PROVISIONER_TLS_SERVER_NAME = "provisioner";

// Export the last HTTP code to allow differentiated retry policies (4xx slow-retry)
static int g_last_prov_http_code = -1;

// Accessor (optional) to retrieve the last HTTP code externally.
int getLastProvisioningHttpCode() { return g_last_prov_http_code; }

/**
 * Parses a standard URL string into its protocol, host, port, and path components.
 */
bool parseProvisioningUrl(const char* url, ProvisioningUrl& out) {
    if (!url) return false;

    String s(url);
    if (s.startsWith("https://")) {
        out.https = true;
        out.port = 443;
        s.remove(0, 8);
    } else if (s.startsWith("http://")) {
        out.https = false;
        out.port = 80;
        s.remove(0, 7);
    } else {
        return false;
    }

    int slash = s.indexOf('/');
    String hostPort = (slash >= 0) ? s.substring(0, slash) : s;
    out.path = (slash >= 0) ? s.substring(slash) : "/";

    int colon = hostPort.lastIndexOf(':');
    if (colon == 0) return false;

    if (colon > 0) {
        out.host = hostPort.substring(0, colon);
        int parsedPort = hostPort.substring(colon + 1).toInt();
        if (parsedPort <= 0 || parsedPort > 65535) return false;
        out.port = static_cast<uint16_t>(parsedPort);
    } else {
        out.host = hostPort;
    }

    return out.host.length() > 0;
}

/**
 * Checks if the system time is valid (post-2026) to ensure TLS certificate verification 
 * won't fail due to an invalid/expired "Not Before" or "Not After" date.
 */
bool isValidTlsEpoch(uint32_t epochSeconds) {
    // Certs are generated in 2026; reject stale RTC values earlier than 2026-01-01.
    return epochSeconds >= MIN_VALID_TLS_EPOCH;
}

static bool hasValidClockForTLS() {
    return isValidTlsEpoch(static_cast<uint32_t>(time(nullptr)));
}

static void logCurrentTimeForTLS() {
    time_t now = time(nullptr);
    struct tm ti;

    Serial.printf("[PROV] Device epoch: %ld\n", (long)now);
    if (localtime_r(&now, &ti)) {
        char timebuf[32];
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &ti);
        Serial.printf("[PROV] Device local time: %s\n", timebuf);
    } else {
        Serial.println("[PROV] Device local time: unavailable");
    }
}

static void logTLSError(WiFiClientSecure& client) {
    char errbuf[256] = {0};
    int err = client.lastError(errbuf, sizeof(errbuf));
    Serial.printf("[PROV] TLS lastError code: %d\n", err);
    if (errbuf[0] != '\0') {
        Serial.printf("[PROV] TLS lastError text: %s\n", errbuf);
    }
}

/**
 * Main provisioning sequence:
 * 1. Generate a Certificate Signing Request (CSR).
 * 2. Send the CSR to the provisioning server via a secure HTTP POST.
 * 3. Parse the server's JSON response containing the issued certificate.
 * 4. Save the issued certificate and CA to Non-Volatile Storage (NVS).
 */
bool performProvisioning(const char* device_id, const char* server_url) {
    g_last_prov_http_code = -1;
    Serial.println("[PROV] Starting provisioning process...");

    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("[PROV] ERROR: WiFi not connected!");
        return false;
    }

    // 1) CSR Generation
    Serial.println("[PROV] Generating CSR...");
    String csr = generateCSR(device_id);
    if (csr.isEmpty()) {
        Serial.println("[PROV] ERROR: Failed to generate CSR");
        return false;
    }
#if defined(DEBUG_MODE) && DEBUG_MODE == 1
    Serial.println("[PROV] CSR Preview:");
    Serial.println(csr.substring(0, 120) + "...");
#endif

    // 2) Prepare JSON Payload
    JsonDocument doc;
    doc["device_id"] = device_id;
    doc["csr"]       = csr;
    doc["peak_power"] = MAX_NOMINAL_POWER;
    doc["bootstrap_token"] = BOOTSTRAP_TOKEN;

    String jsonPayload;
    serializeJson(doc, jsonPayload);

    ProvisioningUrl target;
    if (!parseProvisioningUrl(server_url, target)) {
        Serial.println("[PROV] ERROR: Invalid provisioning URL format");
        return false;
    }

    if (!target.https) {
        Serial.println("[PROV] ERROR: Provisioning URL must use HTTPS");
        return false;
    }

    WiFiClientSecure https;
    const char* tls_ca = nullptr;

#if defined(SKIP_CERT_VERIFICATION) && SKIP_CERT_VERIFICATION == 1
    https.setInsecure();
    Serial.println("[PROV] WARNING: TLS certificate verification DISABLED (dev mode)");
#else
    // During bootstrap, always use embedded CA to avoid stale CA leftovers in NVS.
    const char* ca = nullptr;
    if (isProvisioned()) {
        ca = getCACert();
        Serial.println("[PROV] TLS CA source: NVS (provisioned device)");
    } else {
        ca = CA_CERT;
        Serial.println("[PROV] TLS CA source: embedded bootstrap CA");
    }

    if (!ca) {
        Serial.println("[PROV] ERROR: Missing CA certificate, cannot verify server");
        return false;
    }

    logCurrentTimeForTLS();

    if (!hasValidClockForTLS()) {
        Serial.println("[PROV] ERROR: System time not synchronized; TLS cert validation will fail");
        return false;
    }

    tls_ca = ca;
    https.setCACert(ca);
#endif

    https.setTimeout(HTTP_TIMEOUT / 1000); // seconds

    // 4) TLS connection and manual HTTP POST
    IPAddress targetIp;
    bool hostIsIp = targetIp.fromString(target.host);

    String tlsServerName = target.host;
    if (hostIsIp && PROVISIONER_TLS_SERVER_NAME[0] != '\0') {
        tlsServerName = PROVISIONER_TLS_SERVER_NAME;
        Serial.printf("[PROV] TLS SNI/hostname override: %s\n", tlsServerName.c_str());
    }

    int connected = 0;
    if (hostIsIp) {
        connected = https.connect(targetIp, target.port, tlsServerName.c_str(), tls_ca, nullptr, nullptr);
    } else {
        connected = https.connect(target.host.c_str(), target.port);
    }

    if (!connected) {
        Serial.println("[PROV] ERROR: TLS connect failed");
        logTLSError(https);
        return false;
    }

    String hostHeader = PROVISIONER_HOST_HEADER[0] ? String(PROVISIONER_HOST_HEADER) : tlsServerName;
    if (hostHeader.length() == 0) {
        hostHeader = target.host;
    }

    if (!((target.port == 80 && !target.https) || (target.port == 443 && target.https))) {
        hostHeader += ":" + String(target.port);
    }

    Serial.print("[PROV] Sending CSR to: ");
    Serial.println(server_url);

    String request;
    request.reserve(256 + jsonPayload.length());
    request += "POST ";
    request += target.path;
    request += " HTTP/1.1\r\n";
    request += "Host: ";
    request += hostHeader;
    request += "\r\n";
    request += "Content-Type: application/json\r\n";
    request += "Connection: close\r\n";
    request += "Content-Length: ";
    request += String(jsonPayload.length());
    request += "\r\n\r\n";
    request += jsonPayload;

    size_t written = https.print(request);
    if (written != request.length()) {
        Serial.println("[PROV] ERROR: Failed to send full HTTP request");
        https.stop();
        return false;
    }

    String rawResponse;
    rawResponse.reserve(2048);
    unsigned long lastDataMs = millis();
    while ((millis() - lastDataMs) < HTTP_TIMEOUT) {
        while (https.available()) {
            int c = https.read();
            if (c >= 0) {
                rawResponse += static_cast<char>(c);
                lastDataMs = millis();
            }
        }

        if (!https.connected() && !https.available()) {
            break;
        }
        delay(5);
    }
    https.stop();

    int httpCode = -1;
    int statusLineEnd = rawResponse.indexOf("\r\n");
    if (statusLineEnd > 0) {
        String statusLine = rawResponse.substring(0, statusLineEnd);
        int sp1 = statusLine.indexOf(' ');
        int sp2 = statusLine.indexOf(' ', sp1 + 1);
        if (sp1 > 0 && sp2 > sp1) {
            httpCode = statusLine.substring(sp1 + 1, sp2).toInt();
        }
    }

    g_last_prov_http_code = httpCode;
    Serial.printf("[PROV] HTTP Response Code: %d\n", httpCode);
    Serial.printf("[PROV] RESULT_HTTP_CODE=%d\n", httpCode);

    int bodyStart = rawResponse.indexOf("\r\n\r\n");
    String response = (bodyStart >= 0) ? rawResponse.substring(bodyStart + 4) : String();

    if (httpCode != HTTP_CODE_OK) {
        if (httpCode < 0) {
            Serial.println("[PROV] HTTP Error: invalid/timeout response or connection refused");
            logTLSError(https);
        } else {
            Serial.println("[PROV] Server Error body:");
            Serial.println(response.substring(0, 400));
        }
        return false;
    }

    // 5) Parse server JSON response
    if (response.isEmpty()) {
        Serial.println("[PROV] ERROR: Empty response from server");
        return false;
    }

    String cert;
    String ca_from_srv;

    if (response.startsWith("{")) {
        JsonDocument respDoc;
        DeserializationError error = deserializeJson(respDoc, response);
        if (error) {
            Serial.printf("[PROV] ERROR: JSON parse failed: %s\n", error.c_str());
            return false;
        }
        if (respDoc["certificate"].is<const char*>())
            cert = respDoc["certificate"].as<String>();
        else if (respDoc["cert"].is<const char*>())
            cert = respDoc["cert"].as<String>();
        if (respDoc["ca"].is<const char*>())
            ca_from_srv = respDoc["ca"].as<String>();
        else if (respDoc["ca_cert"].is<const char*>())
            ca_from_srv = respDoc["ca_cert"].as<String>();
        else if (respDoc["ca_certificate"].is<const char*>())
            ca_from_srv = respDoc["ca_certificate"].as<String>();
    } else {
        cert = response;
    }

    if (!cert.startsWith("-----BEGIN CERTIFICATE-----")) {
        Serial.println("[PROV] ERROR: Invalid certificate format received");
        Serial.println(cert.substring(0, 200));
        return false;
    }

    if (!saveCertToNVS(cert.c_str())) {
        Serial.println("[PROV] ERROR: Failed to save certificate to NVS");
        return false;
    }

    if (ca_from_srv.startsWith("-----BEGIN CERTIFICATE-----")) {
        saveCACertToNVS(ca_from_srv.c_str());
    } else {
        const char* bootstrap_ca = getCACert();
        if (bootstrap_ca && bootstrap_ca[0] != '\0') {
            if (!saveCACertToNVS(bootstrap_ca)) {
                Serial.println("[PROV] WARNING: Failed to persist bootstrap CA to NVS");
            } else {
                Serial.println("[PROV] Bootstrap CA persisted to NVS");
            }
        } else {
            Serial.println("[PROV] WARNING: No CA returned by server and no bootstrap CA available");
        }
    }

    Serial.println("[PROV] ===================================");
    Serial.println("[PROV] PROVISIONING COMPLETED SUCCESSFULLY");
    Serial.println("[PROV] ===================================");

    return true;
}

// Overload using default provisioning URL from config
bool performProvisioning(const char* device_id) {
    return performProvisioning(device_id, PROVISIONING_URL);
}