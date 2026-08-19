#include "security_manager.h"
#include "config.h"
#include <nvs_flash.h>
#include <nvs.h>
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/error.h"

// ============================================================================
// Constants
// ============================================================================
static const char* NVS_NAMESPACE = "iot_secure";
static const char* KEY_TAG      = "ecdsa_priv";  // PEM
static const char* CERT_TAG     = "x509_cert";   // PEM
static const char* CA_CERT_TAG  = "ca_cert";     // PEM

// ============================================================================
// Global Contexts
// ============================================================================
static mbedtls_pk_context pk_ctx;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static bool ctx_initialized = false;

// Stored material
static char device_cert_pem[2048] = {0};
static char device_key_pem[2048]  = {0};
static char ca_cert_pem[2048]     = {0};
static bool provisioned = false;
static bool has_ca_cert = false;

// ============================================================================
// Forward declarations
// ============================================================================
static bool loadKeyFromNVS();
static void generateAndSaveKey();
static bool loadCertFromNVS();
static bool loadCACertFromNVS();
static void printMbedtlsError(const char* func, int ret);

// ============================================================================
// Helpers
// ============================================================================
static void printMbedtlsError(const char* func, int ret) {
#if defined(DEBUG_MODE) && DEBUG_MODE == 1
    char error_buf[100];
    mbedtls_strerror(ret, error_buf, sizeof(error_buf));
    Serial.printf("[SECURITY] %s failed: -0x%04X (%s)\n", func, -ret, error_buf);
#else
    (void)func; (void)ret;
#endif
}

// ============================================================================
// Init
// ============================================================================
void initSecurity() {
    Serial.println("[SECURITY] Module initialization...");

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        Serial.println("[SECURITY] Erasing NVS...");
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    mbedtls_pk_init(&pk_ctx);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    const char *pers = "microgrid_secure_meter";
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    (const unsigned char *)pers, strlen(pers));
    if (ret != 0) { printMbedtlsError("ctr_drbg_seed", ret); return; }

    ctx_initialized = true;

    if (!loadKeyFromNVS()) {
        Serial.println("[SECURITY] No key found. Generating new ECDSA pair...");
        generateAndSaveKey();
    } else {
        Serial.println("[SECURITY] Private key loaded.");
    }

    provisioned = loadCertFromNVS();
    has_ca_cert = loadCACertFromNVS();

#if defined(CONFIG_NVS_ENCRYPTION) && CONFIG_NVS_ENCRYPTION == 1
    Serial.println("[SECURITY] ✓ NVS encryption ENABLED");
#else
    Serial.println("[SECURITY] ⚠ NVS encryption DISABLED (enable in prod)");
#endif

    String pubKey = getPublicKeyHex();
    if (pubKey.length() > 0) {
        Serial.print("[SECURITY] PubKey: ");
        Serial.print(pubKey.substring(0, 16));
        Serial.println("...");
    }
}

// ============================================================================
// Key management
// ============================================================================
static bool loadKeyFromNVS() {
    nvs_handle_t h;
    size_t len = sizeof(device_key_pem);
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) return false;
    esp_err_t err = nvs_get_str(h, KEY_TAG, device_key_pem, &len);
    nvs_close(h);
    if (err != ESP_OK || len < 10) { device_key_pem[0] = '\0'; return false; }

    int ret = mbedtls_pk_parse_key(&pk_ctx,
                                   (const unsigned char*)device_key_pem,
                                   strlen(device_key_pem) + 1,
                                   NULL, 0);
    if (ret != 0) { printMbedtlsError("pk_parse_key", ret); device_key_pem[0]='\0'; return false; }
    return true;
}

static void generateAndSaveKey() {
    int ret = mbedtls_pk_setup(&pk_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (ret != 0) { printMbedtlsError("pk_setup", ret); return; }

    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(pk_ctx),
                              mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) { printMbedtlsError("ecp_gen_key", ret); return; }

    ret = mbedtls_pk_write_key_pem(&pk_ctx, (unsigned char*)device_key_pem, sizeof(device_key_pem));
    if (ret != 0) { printMbedtlsError("pk_write_key_pem", ret); return; }

    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_str(h, KEY_TAG, device_key_pem);
        nvs_commit(h);
        nvs_close(h);
        Serial.println("[SECURITY] Keypair generated and saved (PEM).");
    } else {
        Serial.println("[SECURITY] ERROR: Cannot save key to NVS!");
    }
}

// ============================================================================
// Cert management
// ============================================================================
static bool loadCertFromNVS() {
    nvs_handle_t h; size_t len = sizeof(device_cert_pem);
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) return false;
    esp_err_t err = nvs_get_str(h, CERT_TAG, device_cert_pem, &len);
    nvs_close(h);
    return (err == ESP_OK && len > 1);
}

static bool loadCACertFromNVS() {
    nvs_handle_t h; size_t len = sizeof(ca_cert_pem);
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) return false;
    esp_err_t err = nvs_get_str(h, CA_CERT_TAG, ca_cert_pem, &len);
    nvs_close(h);
    return (err == ESP_OK && len > 1);
}

bool saveCertToNVS(const char* cert_pem) {
    if (!cert_pem || strlen(cert_pem) < 10) return false;
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) return false;
    esp_err_t err = nvs_set_str(h, CERT_TAG, cert_pem);
    if (err == ESP_OK) {
        nvs_commit(h);
        strncpy(device_cert_pem, cert_pem, sizeof(device_cert_pem)-1);
        provisioned = true;
        Serial.println("[SECURITY] Device certificate saved.");
    }
    nvs_close(h);
    return (err == ESP_OK);
}

bool saveCACertToNVS(const char* ca_pem) {
    if (!ca_pem || strlen(ca_pem) < 10) return false;
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) return false;
    esp_err_t err = nvs_set_str(h, CA_CERT_TAG, ca_pem);
    if (err == ESP_OK) {
        nvs_commit(h);
        strncpy(ca_cert_pem, ca_pem, sizeof(ca_cert_pem)-1);
        has_ca_cert = true;
        Serial.println("[SECURITY] CA certificate saved.");
    }
    nvs_close(h);
    return (err == ESP_OK);
}

bool isProvisioned() { return provisioned && has_ca_cert; }
const char* getDeviceCert() { return device_cert_pem; }
const char* getDeviceKey()  { return (device_key_pem[0] ? device_key_pem : NULL); }
const char* getCACert() {
    if (has_ca_cert) return ca_cert_pem;

#if !defined(SKIP_CERT_VERIFICATION) || SKIP_CERT_VERIFICATION == 0
    return CA_CERT;
#else
    return nullptr;
#endif
}

// ============================================================================
// Crypto ops
// ============================================================================
String signMessage(const String& message) {
    if (!ctx_initialized) { Serial.println("[SECURITY] ERROR: not initialized"); return ""; }

    unsigned char hash[32], sig[MBEDTLS_ECDSA_MAX_LEN]; size_t sig_len = 0;
    int ret;

    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    mbedtls_sha256_update(&sha, (const unsigned char*)message.c_str(), message.length());
    mbedtls_sha256_finish(&sha, hash);
    mbedtls_sha256_free(&sha);

    ret = mbedtls_pk_sign(&pk_ctx, MBEDTLS_MD_SHA256,
                          hash, sizeof(hash),
                          sig, &sig_len,
                          mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) { printMbedtlsError("pk_sign", ret); return ""; }

    String hex; hex.reserve(sig_len*2);
    for (size_t i=0;i<sig_len;i++){ char h[3]; snprintf(h,3,"%02x",sig[i]); hex+=h; }
    return hex;
}

String getPublicKeyHex() {
    if (!ctx_initialized) return "";
    unsigned char buf[256];
    int ret = mbedtls_pk_write_pubkey_der(&pk_ctx, buf, sizeof(buf));
    if (ret < 0) { printMbedtlsError("pk_write_pubkey_der", ret); return ""; }
    size_t len = ret; unsigned char* start = buf + sizeof(buf) - len;
    String hex; hex.reserve(len*2);
    for (size_t i=0;i<len;i++){ char h[3]; snprintf(h,3,"%02x",start[i]); hex+=h; }
    return hex;
}

uint32_t getNextSequence() {
    nvs_handle_t handle;
    uint32_t seq = 0;

    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        Serial.println("[SECURITY] NVS open failed for sequence counter");
        return 0;
    }

    nvs_get_u32(handle, SEQ_TAG, &seq);   // if doesn't exists stays 0
    seq += 1;
    nvs_set_u32(handle, SEQ_TAG, seq);
    nvs_commit(handle);
    nvs_close(handle);

    return seq;
}

// ============================================================================
// CSR generation
// ============================================================================
String generateCSR(const char* device_id) {
    if (!ctx_initialized || !device_id) return "";

    mbedtls_x509write_csr csr;
    unsigned char csr_buf[1024];
    char subject[128];
    int ret;

    mbedtls_x509write_csr_init(&csr);
    snprintf(subject, sizeof(subject), "CN=%s,O=SmartMicroGrid,C=IT", device_id);

    ret = mbedtls_x509write_csr_set_subject_name(&csr, subject);
    if (ret != 0) { printMbedtlsError("set_subject_name", ret); mbedtls_x509write_csr_free(&csr); return ""; }

    mbedtls_x509write_csr_set_key(&csr, &pk_ctx);
    mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);

    ret = mbedtls_x509write_csr_pem(&csr, csr_buf, sizeof(csr_buf),
                                    mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_x509write_csr_free(&csr);

    if (ret != 0) { printMbedtlsError("x509write_csr_pem", ret); return ""; }

    return String((char*)csr_buf);
}