#ifndef SENSOR_MANAGER_H
#define SENSOR_MANAGER_H

#include <Arduino.h>

/**
 * Structure for energy data (Smart Meter).
 * Represents the reading xi,t of the Trust model.
 */
struct EnergyData {
    float voltage;      // Grid voltage (V)
    float current;      // Generated current (A)
    float power;        // Active power produced (W)
    uint32_t timestamp; // Reading timestamp (Unix epoch)
};

/**
 * Initializes the sensor module.
 * In SIMULATION_MODE:  no hardware init required.
 * In production: initializes ADC for real sensors.
 */
void initSensors();

/**
 * Reads energy data from sensors or simulator.
 * Automatically selects based on SIMULATION_MODE flag.
 */
EnergyData readSensorData();

/**
 * Generates synthetic data based on forecast yield (Open-Meteo or fallback).
 * Only available in SIMULATION_MODE.
 */
EnergyData readSimulatedData();

/**
 * Builds a deterministic simulated reading from yield percentage and noise inputs.
 * Useful for unit tests and for isolating the simulation model.
 */
EnergyData buildSimulatedEnergyData(float yieldPercentage,
                                    uint32_t timestamp,
                                    float powerNoiseFactor,
                                    float voltageOffset);

#endif // SENSOR_MANAGER_H