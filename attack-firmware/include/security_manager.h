#pragma once
#ifndef SECURITY_MANAGER_H
#define SECURITY_MANAGER_H

#include <Arduino.h>

/** Initializes crypto + NVS. Generates key if missing. */
void initSecurity();

/** Signs a message with ECDSA P-256, returns hex string. */
String signMessage(const String& message);

/** Returns public key in hex (DER). */
String getPublicKeyHex();

// ========== Provisioning ==========
String generateCSR(const char* device_id);
bool saveCertToNVS(const char* cert_pem);
bool saveCACertToNVS(const char* ca_pem);
bool isProvisioned();

const char* getDeviceCert();  // PEM
const char* getDeviceKey();   // PEM
const char* getCACert();      // PEM (NVS or embedded)

#endif // SECURITY_MANAGER_H