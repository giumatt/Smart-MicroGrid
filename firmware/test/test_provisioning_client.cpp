#include <unity.h>
#include "provisioning_client.h"

void test_parseProvisioningUrl_supports_https_defaults() {
    ProvisioningUrl url;

    bool ok = parseProvisioningUrl("https://enroll.example.com/enroll", url);

    TEST_ASSERT_TRUE(ok);
    TEST_ASSERT_EQUAL_STRING("enroll.example.com", url.host.c_str());
    TEST_ASSERT_TRUE(url.https);
    TEST_ASSERT_EQUAL_UINT16(443, url.port);
    TEST_ASSERT_EQUAL_STRING("/enroll", url.path.c_str());
}

void test_parseProvisioningUrl_supports_http_custom_port() {
    ProvisioningUrl url;

    bool ok = parseProvisioningUrl("http://192.168.1.50:5000/enroll", url);

    TEST_ASSERT_TRUE(ok);
    TEST_ASSERT_EQUAL_STRING("192.168.1.50", url.host.c_str());
    TEST_ASSERT_FALSE(url.https);
    TEST_ASSERT_EQUAL_UINT16(5000, url.port);
    TEST_ASSERT_EQUAL_STRING("/enroll", url.path.c_str());
}

void test_parseProvisioningUrl_rejects_invalid_input() {
    ProvisioningUrl url;

    TEST_ASSERT_FALSE(parseProvisioningUrl(nullptr, url));
    TEST_ASSERT_FALSE(parseProvisioningUrl("ftp://example.com", url));
    TEST_ASSERT_FALSE(parseProvisioningUrl("https://:8443/enroll", url));
}

void test_isValidTlsEpoch_enforces_minimum_bootstrap_time() {
    TEST_ASSERT_FALSE(isValidTlsEpoch(1767225599UL));
    TEST_ASSERT_TRUE(isValidTlsEpoch(1767225600UL));
    TEST_ASSERT_TRUE(isValidTlsEpoch(1767225601UL));
}