#include <Arduino.h>
#include <unity.h>

void test_parseProvisioningUrl_supports_https_defaults();
void test_parseProvisioningUrl_supports_http_custom_port();
void test_parseProvisioningUrl_rejects_invalid_input();
void test_isValidTlsEpoch_enforces_minimum_bootstrap_time();
void test_buildSimulatedEnergyData_returns_zero_at_night();
void test_buildSimulatedEnergyData_peaks_at_midday_without_noise();
void test_buildSimulatedEnergyData_applies_noise_inputs();

void setup() {
	delay(1500);

	UNITY_BEGIN();
	RUN_TEST(test_parseProvisioningUrl_supports_https_defaults);
	RUN_TEST(test_parseProvisioningUrl_supports_http_custom_port);
	RUN_TEST(test_parseProvisioningUrl_rejects_invalid_input);
	RUN_TEST(test_isValidTlsEpoch_enforces_minimum_bootstrap_time);
	RUN_TEST(test_buildSimulatedEnergyData_returns_zero_at_night);
	RUN_TEST(test_buildSimulatedEnergyData_peaks_at_midday_without_noise);
	RUN_TEST(test_buildSimulatedEnergyData_applies_noise_inputs);
	UNITY_END();
}

void loop() {}

// Unity test hooks
void setUp() {}
void tearDown() {}