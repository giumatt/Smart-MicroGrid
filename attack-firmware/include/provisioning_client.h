#ifndef PROVISIONING_CLIENT_H
#define PROVISIONING_CLIENT_H

#include <Arduino.h>

struct ProvisioningUrl {
	String host;
	uint16_t port;
	String path;
	bool https;
};

/**
 * Parses a provisioning URL into scheme, host, port and path.
 */
bool parseProvisioningUrl(const char* url, ProvisioningUrl& out);

/**
 * Returns whether the provided epoch is recent enough for TLS validation.
 */
bool isValidTlsEpoch(uint32_t epochSeconds);

/**
 * Performs the full provisioning flow:
 * 1. Generate CSR with device keys
 * 2. Send CSR to Enrollment Server via HTTPS POST
 * 3. Receive signed X.509 certificate
 * 4. Store certificate in NVS
 *
 * @param device_id Unique device identifier (e.g., "SmartMeter_001")
 * @param server_url Provisioning server URL (e.g., "https://192.168.1.100:5000/enroll")
 * @return true if provisioning successful
 */
bool performProvisioning(const char* device_id, const char* server_url);

/**
 * Simplified version using default server URL from config.h
 */
bool performProvisioning(const char* device_id);

/**
 * Returns the last HTTP status code observed during provisioning.
 * -1 means no valid HTTP response / connection failed / parse failed.
 */
int getLastProvisioningHttpCode();

#endif