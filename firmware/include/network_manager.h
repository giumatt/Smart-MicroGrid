#ifndef NETWORK_MANAGER_H
#define NETWORK_MANAGER_H

#include <Arduino.h>
#include <ArduinoJson.h>

/**
 * Initializes Wi-Fi connection and NTP time synchronization.
 * Does NOT connect to MQTT yet.
 */
void initNetwork();

/**
 * Initializes MQTT connection (call after provisioning in production).
 * In development mode, uses insecure connection.
 * In production mode, uses TLS with client certificate.
 */
void initMQTT();

/**
 * Maintains connection to the MQTT broker. 
 * Handles automatic reconnection. 
 */
void maintainLink();

/**
 * Sends the signed JSON packet to the gateway.
 * @return true if sent successfully
 */
bool sendData(JsonDocument& doc);

/**
 * Checks if the system is ready to transmit.
 * @return true if WiFi and MQTT are connected
 */
bool isConnected();

#endif // NETWORK_MANAGER_H