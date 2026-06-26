#include <unity.h>
#include "sensor_manager.h"
#include "config.h"

void test_buildSimulatedEnergyData_returns_zero_at_night() {
    EnergyData data = buildSimulatedEnergyData(0.0f, 1234567890UL, 0.0f, 0.0f);

    TEST_ASSERT_FLOAT_WITHIN(0.001f, 0.0f, data.power);
    TEST_ASSERT_FLOAT_WITHIN(0.001f, 230.0f, data.voltage);
    TEST_ASSERT_FLOAT_WITHIN(0.001f, 0.0f, data.current);
    TEST_ASSERT_EQUAL_UINT32(1234567890UL, data.timestamp);
}

void test_buildSimulatedEnergyData_peaks_at_midday_without_noise() {
    EnergyData data = buildSimulatedEnergyData(1.0f, 42UL, 0.0f, 0.0f);

    TEST_ASSERT_FLOAT_WITHIN(0.01f, MAX_NOMINAL_POWER, data.power);
    TEST_ASSERT_FLOAT_WITHIN(0.001f, 230.0f, data.voltage);
    TEST_ASSERT_FLOAT_WITHIN(0.01f, MAX_NOMINAL_POWER / 230.0f, data.current);
    TEST_ASSERT_EQUAL_UINT32(42UL, data.timestamp);
}

void test_buildSimulatedEnergyData_applies_noise_inputs() {
    EnergyData data = buildSimulatedEnergyData(0.5f, 99UL, 0.02f, -0.5f);

    TEST_ASSERT_TRUE(data.power > 0.0f);
    TEST_ASSERT_FLOAT_WITHIN(0.001f, 229.5f, data.voltage);
    TEST_ASSERT_EQUAL_UINT32(99UL, data.timestamp);
}