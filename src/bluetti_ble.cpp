// =============================================================================
// bluetti_ble.cpp
// =============================================================================
// Talks to a Bluetti power station over Bluetooth LE: connects, performs the
// station's proprietary encryption handshake, and reads Modbus-style
// registers (battery %, power in/out, voltage). Protocol details (framing,
// crypto, register map) are transcribed from the open-source Python project
// github.com/Patrick762/bluetti-bt-lib (bluetooth/device_reader.py,
// bluetooth/encryption.py, registers/*.py, devices/ac180p.py).
//
// If you're coming from C#: this file has no classes. State that would be
// instance fields in C# lives in one global struct (`BluettiState g`, see
// SECTION 5) instead, and "methods" are just functions that read/write `g`.
// That's a normal C pattern - there's no object to `new` up, so a single
// global stands in for "the one station connection we support".
// =============================================================================

#include <string.h>
#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "esp_log.h"
#include "esp_timer.h"

// --- NimBLE (Bluetooth LE stack bundled with ESP-IDF) -----------------------
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/ble_hs_id.h"
#include "host/ble_uuid.h"
#include "host/util/util.h"
#include "os/os_mbuf.h"

// --- mbedtls, via the PSA Crypto API ----------------------------------------
// This ESP-IDF version only exposes crypto through psa_xxx() functions, not
// the older mbedtls_aes_xxx()/mbedtls_ecdh_xxx() names.
#include "psa/crypto.h"

#include "bluetti_ble.h"

static const char *TAG = "bluetti_ble";

// =============================================================================
// SECTION 1: Protocol constants
// =============================================================================

// The station exposes one custom BLE service with two characteristics
// (16-bit UUIDs, expanded to the standard 128-bit Bluetooth Base UUID under
// the hood). We write commands to WRITE_UUID and get responses as
// notifications on NOTIFY_UUID - a push from the peripheral, not a return
// value, so we always wait on it separately (see sem_response in SECTION 5).
#define BLUETTI_NOTIFY_UUID16 0xFF01
#define BLUETTI_WRITE_UUID16  0xFF02

// --- Fixed cryptographic material -------------------------------------------
// Same for every station of this generation - not secrets unique to your
// unit, just constants baked into the protocol (and into bluetti-bt-lib).

// XOR'd with a per-connection value to derive the bootstrap AES key used
// only for the first couple of handshake messages.
static const uint8_t LOCAL_AES_KEY[16] = {
    0x45, 0x9F, 0xC5, 0x35, 0x80, 0x89, 0x41, 0xF1,
    0x70, 0x91, 0xE0, 0x99, 0x3E, 0xE3, 0xE9, 0x3D,
};

// Our long-term ECDSA signing key (secp256r1 private scalar) - proves to the
// station we're speaking the real protocol.
static const uint8_t PRIVATE_KEY_L1[32] = {
    0x4F, 0x19, 0xA1, 0x6E, 0x3E, 0x87, 0xBD, 0xD9,
    0xBD, 0x24, 0xD3, 0xE5, 0x49, 0x5B, 0x88, 0x04,
    0x15, 0x11, 0x94, 0x3C, 0xBC, 0x8B, 0x96, 0x9A,
    0xDE, 0x96, 0x41, 0xD0, 0xF5, 0x6A, 0xF3, 0x37,
};

// The station's long-term ECDSA public key (secp256r1 uncompressed point,
// X||Y, 64 bytes) - used to verify the station's ephemeral key is genuine.
static const uint8_t PUBLIC_KEY_K2_XY[64] = {
    0xA7, 0x3A, 0xBF, 0x5D, 0x22, 0x32, 0xC8, 0xC1,
    0xC7, 0x2E, 0x68, 0x30, 0x43, 0x43, 0xC2, 0x72,
    0x49, 0x5E, 0x3A, 0x8F, 0xD6, 0xF3, 0x0E, 0xA9,
    0x6D, 0xE2, 0xF4, 0xB3, 0xCE, 0x60, 0xB2, 0x51,
    0xEE, 0x21, 0xAC, 0x66, 0x7C, 0xF8, 0xA7, 0x1E,
    0x18, 0xB4, 0x6B, 0x66, 0x4E, 0xAE, 0xFF, 0xE3,
    0xC4, 0x89, 0xF2, 0x4F, 0x69, 0x5B, 0x64, 0x11,
    0xDB, 0x7E, 0x22, 0xCC, 0xC8, 0x5A, 0x85, 0x94,
};

// Marks the start of every handshake message (not used once encrypted
// register traffic is flowing).
static const uint8_t KEX_MAGIC[2] = {0x2A, 0x2A}; // "**"

// Handshake message types, as sent by the STATION to us.
enum HandshakeMsgType {
    MSG_CHALLENGE          = 1,
    MSG_CHALLENGE_ACCEPTED = 3,
    MSG_PEER_PUBKEY        = 4,
    MSG_PUBKEY_ACCEPTED    = 6,
};

// --- Register map ------------------------------------------------------------
// Modbus-style "register address" -> single 16-bit word unless noted.
#define REG_BATTERY_SOC       102   // 0-100 (%)
#define REG_DC_OUTPUT_POWER   140   // Watts
#define REG_AC_OUTPUT_POWER   142   // Watts
#define REG_DC_INPUT_POWER    144   // Watts
#define REG_AC_INPUT_POWER    146   // Watts
#define REG_AC_INPUT_VOLTAGE  1314  // raw value is Volts*10
#define REG_DEVICE_TYPE       110   // 6 words (12 bytes) - an ASCII string, not a number; see read_device_type()
#define REG_DEVICE_TYPE_WORDS 6
#define REG_CTRL_AC            2011  // AC output switch: 0 = off, 1 = on (readable + writable)
#define REG_CTRL_DC            2012  // DC output switch: 0 = off, 1 = on (readable + writable)

// Modbus function codes this file uses: "read holding registers", and
// "write single register" (for the AC/DC output switches).
#define MODBUS_READ_FUNCTION  3
#define MODBUS_WRITE_FUNCTION 6

// =============================================================================
// SECTION 2: Small self-contained helpers (CRC16, MD5)
// =============================================================================

// CRC-16/MODBUS: reflected CRC-16, polynomial 0xA001, initial value 0xFFFF.
// Same algorithm as Python's crcmod.predefined.mkCrcFun("modbus").
static uint16_t modbus_crc16(const uint8_t *data, size_t len)
{
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; bit++) {
            if (crc & 0x0001) {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc = crc >> 1;
            }
        }
    }
    return crc;
}

// The handshake's own "checksum" - not cryptographic, just a sum of the body
// bytes truncated to `out_len` bytes, big-endian. Ports Python's hexsum().
static void body_checksum(const uint8_t *body, size_t len, uint8_t out[2])
{
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += body[i];
    }
    out[0] = (uint8_t)((sum >> 8) & 0xFF);
    out[1] = (uint8_t)(sum & 0xFF);
}

// Minimal MD5 (RFC 1321), needed only because the protocol's key-derivation
// step (see handle_challenge) uses it - not for anything security-sensitive.
// Self-contained so this file doesn't depend on whatever MD5 support may or
// may not be wired into the PSA crypto config.
namespace {
struct Md5Ctx {
    uint32_t a, b, c, d;
    uint64_t bit_count;
    uint8_t buffer[64];
    size_t buffer_len;
};

static inline uint32_t rotl32(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }

static void md5_process_block(Md5Ctx *ctx, const uint8_t block[64])
{
    static const uint32_t K[64] = {
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391,
    };
    static const int S[64] = {
        7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
        5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
        4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
        6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21,
    };

    uint32_t M[16];
    for (int i = 0; i < 16; i++) {
        M[i] = (uint32_t)block[i*4] | ((uint32_t)block[i*4+1] << 8) |
               ((uint32_t)block[i*4+2] << 16) | ((uint32_t)block[i*4+3] << 24);
    }

    uint32_t A = ctx->a, B = ctx->b, C = ctx->c, D = ctx->d;
    for (int i = 0; i < 64; i++) {
        uint32_t F; int g;
        if (i < 16) { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5*i + 1) % 16; }
        else if (i < 48) { F = B ^ C ^ D; g = (3*i + 5) % 16; }
        else { F = C ^ (B | ~D); g = (7*i) % 16; }

        F = F + A + K[i] + M[g];
        A = D; D = C; C = B;
        B = B + rotl32(F, S[i]);
    }

    ctx->a += A; ctx->b += B; ctx->c += C; ctx->d += D;
}

static void md5_init(Md5Ctx *ctx)
{
    ctx->a = 0x67452301; ctx->b = 0xefcdab89;
    ctx->c = 0x98badcfe; ctx->d = 0x10325476;
    ctx->bit_count = 0;
    ctx->buffer_len = 0;
}

static void md5_update(Md5Ctx *ctx, const uint8_t *data, size_t len)
{
    ctx->bit_count += (uint64_t)len * 8;
    while (len > 0) {
        size_t take = 64 - ctx->buffer_len;
        if (take > len) take = len;
        memcpy(ctx->buffer + ctx->buffer_len, data, take);
        ctx->buffer_len += take;
        data += take;
        len -= take;
        if (ctx->buffer_len == 64) {
            md5_process_block(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }
}

static void md5_final(Md5Ctx *ctx, uint8_t out[16])
{
    uint64_t bit_count = ctx->bit_count;
    uint8_t pad = 0x80;
    md5_update(ctx, &pad, 1);
    uint8_t zero = 0x00;
    while (ctx->buffer_len != 56) {
        md5_update(ctx, &zero, 1);
    }
    uint8_t len_bytes[8];
    for (int i = 0; i < 8; i++) {
        len_bytes[i] = (uint8_t)((bit_count >> (8 * i)) & 0xFF);
    }
    md5_update(ctx, len_bytes, 8);

    uint32_t words[4] = {ctx->a, ctx->b, ctx->c, ctx->d};
    for (int i = 0; i < 4; i++) {
        out[i*4 + 0] = (uint8_t)(words[i] & 0xFF);
        out[i*4 + 1] = (uint8_t)((words[i] >> 8) & 0xFF);
        out[i*4 + 2] = (uint8_t)((words[i] >> 16) & 0xFF);
        out[i*4 + 3] = (uint8_t)((words[i] >> 24) & 0xFF);
    }
}

static void md5(const uint8_t *data, size_t len, uint8_t out[16])
{
    Md5Ctx ctx;
    md5_init(&ctx);
    md5_update(&ctx, data, len);
    md5_final(&ctx, out);
}
} // namespace

// =============================================================================
// SECTION 3: AES-CBC helpers (via PSA Crypto)
// =============================================================================
// Matches the wire format used by bluetti-bt-lib's aes_encrypt()/aes_decrypt():
//   - iv == NULL: a random 4-byte seed is generated, iv = md5(seed), and the
//     output is [2-byte plaintext length][4-byte seed][ciphertext].
//   - iv given: caller already knows the iv, output is just
//     [2-byte plaintext length][ciphertext].
//   - Either way the plaintext is zero-padded (not PKCS7) to a 16-byte
//     multiple before encrypting, and decrypt truncates back to the
//     declared length afterward.
//
// C# note: PSA's `key_id` here is a lot like an IDisposable/SafeHandle -
// psa_import_key "acquires" it, psa_destroy_key releases it, and every
// function below is careful to release it on every exit path (there's no
// `using`/finally to do that for you).

// Encrypts `plain_len` bytes with AES-CBC. `key_len` (16 or 32) selects
// AES-128 vs AES-256 - see BluettiState::secure_aes_key for why both are
// needed in this file. `iv16 == NULL` embeds a fresh random IV (see header
// comment above); otherwise the given 16-byte IV is used as-is.
static bool aes_cbc_encrypt(const uint8_t *plain, size_t plain_len,
                            const uint8_t *key, size_t key_len, const uint8_t *iv16,
                            uint8_t *out, size_t out_cap, size_t *out_len)
{
    uint8_t local_iv[16];
    size_t header_len;
    uint8_t header[6];

    if (iv16 == nullptr) {
        uint8_t seed[4];
        // Uses PSA's RNG (backed by the ESP32's hardware RNG) rather than
        // esp_fill_random(), to avoid an extra dependency.
        if (psa_generate_random(seed, sizeof(seed)) != PSA_SUCCESS) {
            return false;
        }
        md5(seed, sizeof(seed), local_iv);
        header[0] = (uint8_t)((plain_len >> 8) & 0xFF);
        header[1] = (uint8_t)(plain_len & 0xFF);
        memcpy(header + 2, seed, 4);
        header_len = 6;
        iv16 = local_iv;
    } else {
        header[0] = (uint8_t)((plain_len >> 8) & 0xFF);
        header[1] = (uint8_t)(plain_len & 0xFF);
        header_len = 2;
    }

    size_t padded_len = ((plain_len + 15) / 16) * 16;
    if (padded_len == 0) padded_len = 16; // AES-CBC always needs >= 1 block
    if (header_len + padded_len > out_cap) {
        ESP_LOGE(TAG, "aes_cbc_encrypt: output buffer too small");
        return false;
    }

    // Zero-pad into a scratch buffer - Python does `data += bytes(padding)`,
    // i.e. plain zero bytes, not PKCS7.
    uint8_t padded[256]; // generous - our commands/handshake bodies are small
    if (padded_len > sizeof(padded)) {
        ESP_LOGE(TAG, "aes_cbc_encrypt: message too large for scratch buffer");
        return false;
    }
    memset(padded, 0, padded_len);
    memcpy(padded, plain, plain_len);

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, key_len * 8); // 16 bytes -> AES-128, 32 bytes -> AES-256
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_CBC_NO_PADDING);

    mbedtls_svc_key_id_t key_id;
    if (psa_import_key(&attr, key, key_len, &key_id) != PSA_SUCCESS) {
        ESP_LOGE(TAG, "aes_cbc_encrypt: psa_import_key failed");
        return false;
    }

    psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
    bool ok = false;
    size_t written = 0;
    do {
        if (psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_CBC_NO_PADDING) != PSA_SUCCESS) break;
        if (psa_cipher_set_iv(&op, iv16, 16) != PSA_SUCCESS) break;
        size_t part_len = 0;
        if (psa_cipher_update(&op, padded, padded_len,
                               out + header_len, out_cap - header_len, &part_len) != PSA_SUCCESS) break;
        written += part_len;
        size_t final_len = 0;
        if (psa_cipher_finish(&op, out + header_len + written,
                               out_cap - header_len - written, &final_len) != PSA_SUCCESS) break;
        written += final_len;
        ok = true;
    } while (0);

    psa_cipher_abort(&op); // safe to call even after a successful finish
    psa_destroy_key(key_id);

    if (!ok) {
        ESP_LOGE(TAG, "aes_cbc_encrypt: cipher operation failed");
        return false;
    }

    memcpy(out, header, header_len);
    *out_len = header_len + written;
    return true;
}

// Decrypts a buffer using the same framing as aes_cbc_encrypt() above.
//   - `iv16 == NULL`: buffer is [2-byte length][4-byte seed][cipher], IV is
//     re-derived as md5(seed) (the "secure phase" case).
//   - `iv16` given: buffer is [2-byte length][cipher], that exact IV is used
//     (the "unsecure phase" case).
// Output is truncated to the declared plaintext length. `key_len` (16 or
// 32) selects AES-128 vs AES-256, same as aes_cbc_encrypt() above.
static bool aes_cbc_decrypt(const uint8_t *data, size_t data_len,
                            const uint8_t *key, size_t key_len, const uint8_t *iv16,
                            uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (data_len < 2) return false;
    size_t declared_len = ((size_t)data[0] << 8) | data[1];

    const uint8_t *cipher;
    size_t cipher_len;
    uint8_t local_iv[16];

    if (iv16 == nullptr) {
        if (data_len < 6) return false;
        md5(data + 2, 4, local_iv);
        cipher = data + 6;
        cipher_len = data_len - 6;
        iv16 = local_iv;
    } else {
        cipher = data + 2;
        cipher_len = data_len - 2;
    }

    if (cipher_len == 0 || (cipher_len % 16) != 0) {
        ESP_LOGE(TAG, "aes_cbc_decrypt: ciphertext not block-aligned (len=%u)", (unsigned)cipher_len);
        return false;
    }

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, key_len * 8); // 16 bytes -> AES-128, 32 bytes -> AES-256
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_CBC_NO_PADDING);

    mbedtls_svc_key_id_t key_id;
    if (psa_import_key(&attr, key, key_len, &key_id) != PSA_SUCCESS) {
        ESP_LOGE(TAG, "aes_cbc_decrypt: psa_import_key failed");
        return false;
    }

    uint8_t plain[256];
    if (cipher_len > sizeof(plain)) {
        psa_destroy_key(key_id);
        ESP_LOGE(TAG, "aes_cbc_decrypt: message too large for scratch buffer");
        return false;
    }

    psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
    bool ok = false;
    size_t written = 0;
    do {
        if (psa_cipher_decrypt_setup(&op, key_id, PSA_ALG_CBC_NO_PADDING) != PSA_SUCCESS) break;
        if (psa_cipher_set_iv(&op, iv16, 16) != PSA_SUCCESS) break;
        size_t part_len = 0;
        if (psa_cipher_update(&op, cipher, cipher_len, plain, sizeof(plain), &part_len) != PSA_SUCCESS) break;
        written += part_len;
        size_t final_len = 0;
        if (psa_cipher_finish(&op, plain + written, sizeof(plain) - written, &final_len) != PSA_SUCCESS) break;
        written += final_len;
        ok = true;
    } while (0);

    psa_cipher_abort(&op);
    psa_destroy_key(key_id);

    if (!ok) {
        ESP_LOGE(TAG, "aes_cbc_decrypt: cipher operation failed");
        return false;
    }

    if (declared_len > written || declared_len > out_cap) {
        ESP_LOGE(TAG, "aes_cbc_decrypt: declared length out of range");
        return false;
    }

    memcpy(out, plain, declared_len);
    *out_len = declared_len;
    return true;
}

// =============================================================================
// SECTION 4: Elliptic-curve helpers (ECDH + ECDSA via PSA Crypto)
// =============================================================================
// All secp256r1 ("P-256"/"prime256v1").
//
// Format note: PSA represents an uncompressed EC public key as 0x04 followed
// by the 32-byte X coordinate then the 32-byte Y coordinate (65 bytes) - the
// same layout Python's `cryptography` library uses internally. So
// converting between our 64-byte X||Y constants and PSA's format is just
// prepending/stripping one 0x04 byte - no ASN.1/DER parsing needed (PSA's
// sign/verify works with raw signatures directly; Python needs DER because
// the `cryptography` library's API requires it).

// Signs `hash32` with our long-term key (PRIVATE_KEY_L1), producing a raw
// 64-byte (r||s) signature - the format the station expects on the wire.
static bool ecdsa_sign_with_l1(const uint8_t hash32[32], uint8_t sig64[64])
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    mbedtls_svc_key_id_t key_id;
    if (psa_import_key(&attr, PRIVATE_KEY_L1, sizeof(PRIVATE_KEY_L1), &key_id) != PSA_SUCCESS) {
        ESP_LOGE(TAG, "ecdsa_sign_with_l1: failed to import signing key");
        return false;
    }

    size_t sig_len = 0;
    psa_status_t status = psa_sign_hash(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                         hash32, 32, sig64, 64, &sig_len);
    psa_destroy_key(key_id);

    if (status != PSA_SUCCESS || sig_len != 64) {
        ESP_LOGE(TAG, "ecdsa_sign_with_l1: psa_sign_hash failed (status=%d len=%u)",
                 (int)status, (unsigned)sig_len);
        return false;
    }
    return true;
}

// Verifies a raw 64-byte (r||s) signature over `hash32` using the station's
// long-term public key (PUBLIC_KEY_K2_XY).
static bool ecdsa_verify_with_k2(const uint8_t hash32[32], const uint8_t sig64[64])
{
    uint8_t pub_point[65];
    pub_point[0] = 0x04; // "uncompressed point" marker
    memcpy(pub_point + 1, PUBLIC_KEY_K2_XY, 64);

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    mbedtls_svc_key_id_t key_id;
    if (psa_import_key(&attr, pub_point, sizeof(pub_point), &key_id) != PSA_SUCCESS) {
        ESP_LOGE(TAG, "ecdsa_verify_with_k2: failed to import verify key");
        return false;
    }

    psa_status_t status = psa_verify_hash(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                           hash32, 32, sig64, 64);
    psa_destroy_key(key_id);

    if (status != PSA_SUCCESS) {
        ESP_LOGW(TAG, "ecdsa_verify_with_k2: signature check failed (status=%d)", (int)status);
        return false;
    }
    return true;
}

// Generates a fresh random ECDH keypair for this session and exports the
// public part as an uncompressed point (65 bytes: 0x04 || X || Y).
// `*out_priv_key_id` must later be passed to ecdh_compute_shared() and then
// destroyed with psa_destroy_key() once you're done with it.
static bool ecdh_generate_ephemeral_keypair(mbedtls_svc_key_id_t *out_priv_key_id,
                                            uint8_t pub_point65[65])
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);

    if (psa_generate_key(&attr, out_priv_key_id) != PSA_SUCCESS) {
        ESP_LOGE(TAG, "ecdh_generate_ephemeral_keypair: psa_generate_key failed");
        return false;
    }

    size_t len = 0;
    if (psa_export_public_key(*out_priv_key_id, pub_point65, 65, &len) != PSA_SUCCESS || len != 65) {
        ESP_LOGE(TAG, "ecdh_generate_ephemeral_keypair: psa_export_public_key failed");
        psa_destroy_key(*out_priv_key_id);
        return false;
    }
    return true;
}

// Computes the raw ECDH shared secret (X coordinate of the shared point, 32
// bytes - matching Python's `private.exchange(ec.ECDH(), peer_pubkey)`)
// between our ephemeral private key and the station's ephemeral public key
// (peer_point65: 0x04 || X || Y, 65 bytes).
static bool ecdh_compute_shared(mbedtls_svc_key_id_t my_priv_key_id,
                                const uint8_t peer_point65[65],
                                uint8_t out_shared32[32])
{
    size_t len = 0;
    psa_status_t status = psa_raw_key_agreement(PSA_ALG_ECDH, my_priv_key_id,
                                                 peer_point65, 65,
                                                 out_shared32, 32, &len);
    if (status != PSA_SUCCESS || len != 32) {
        ESP_LOGE(TAG, "ecdh_compute_shared: psa_raw_key_agreement failed (status=%d)", (int)status);
        return false;
    }
    return true;
}

// One-shot SHA-256 (ECDSA signs/verifies a hash, not the raw message).
static void sha256(const uint8_t *data, size_t len, uint8_t out32[32])
{
    size_t out_len = 0;
    // No failure handling: a failure here means a broken build config, and
    // execution just continues with an all-zero digest, which safely fails
    // the signature checks downstream.
    psa_hash_compute(PSA_ALG_SHA_256, data, len, out32, 32, &out_len);
}

// =============================================================================
// SECTION 5: The BLE + handshake state machine
// =============================================================================

// Handshake progress, mirroring bluetti-bt-lib's BluettiEncryption state
// (there it's tracked implicitly by which fields are non-null; here it's an
// explicit enum).
enum HandshakeStage {
    HS_NOT_STARTED = 0,
    HS_GOT_UNSECURE_KEY,     // responded to CHALLENGE, waiting for more
    HS_GOT_PEER_PUBKEY,      // sent our signed pubkey, waiting for confirmation
    HS_READY,                // secure_aes_key derived - normal traffic can flow
};

// One raw BLE notification, copied out of NimBLE's own buffers so it can be
// handed off to a different task to process (see notify_worker_task()).
// Plain struct, no pointers - so a byte-for-byte copy (what FreeRTOS queues
// do internally) is always safe.
struct NotifyItem {
    uint8_t data[256];
    size_t len;
};

// All mutable state for "one connection at a time" (this station only
// accepts one BLE central anyway). C# analogy: this is what would be
// instance fields on a singleton service - just a plain global struct here,
// since C has no classes and nothing to `new` up.
struct BluettiState {
    // --- BLE plumbing ---
    bool nimble_started = false;          // has nimble_port_init() run yet?
    uint8_t own_addr_type = 0;
    ble_addr_t target_addr = {};
    bool have_target_addr = false;

    uint16_t conn_handle = BLE_HS_CONN_HANDLE_NONE;
    uint16_t write_val_handle = 0;
    uint16_t notify_val_handle = 0;
    uint16_t notify_def_handle = 0;
    uint16_t cccd_handle = 0;

    // FreeRTOS semaphores are close to C#'s SemaphoreSlim/ManualResetEvent:
    // a task blocks on xSemaphoreTake() until another task calls
    // xSemaphoreGive(). Used here to make async BLE callbacks look
    // synchronous to callers like connect_to_bluetti() and get_all_data().
    SemaphoreHandle_t sem_sync = nullptr;       // NimBLE host stack is up
    SemaphoreHandle_t sem_gap_step = nullptr;   // one BLE step finished (connect/discover/subscribe)
    SemaphoreHandle_t sem_handshake = nullptr;  // encryption handshake finished
    SemaphoreHandle_t sem_response = nullptr;   // a command response arrived
    SemaphoreHandle_t sem_disconnect = nullptr; // the BLE link is actually torn down (see stop_connection())
    SemaphoreHandle_t mutex = nullptr;          // guards get_all_data() against re-entry

    // Hands raw notifications off from the NimBLE host task to
    // notify_worker_task() (a separate task with a bigger stack) - see that
    // function's comment.
    QueueHandle_t notify_queue = nullptr;

    volatile bool gap_step_ok = false;
    volatile bool handshake_ok = false;

    bool use_encryption = false;

    // --- Encryption handshake state (mirrors bluetti-bt-lib's BluettiEncryption) ---
    HandshakeStage stage = HS_NOT_STARTED;
    uint8_t unsecure_aes_key[16] = {0};  // AES-128 key, handshake-phase traffic only
    uint8_t unsecure_aes_iv[16] = {0};
    // Raw 32-byte ECDH shared secret, used AS-IS as an AES-256 key for all
    // post-handshake traffic. This is a different AES variant than
    // unsecure_aes_key above (AES-128) - the two phases use different key
    // sizes, which is why aes_cbc_encrypt()/aes_cbc_decrypt() take an
    // explicit key_len instead of assuming 16 bytes everywhere.
    uint8_t secure_aes_key[32] = {0};
    uint8_t peer_pubkey[65] = {0};    // 0x04 || X || Y
    mbedtls_svc_key_id_t my_ephemeral_priv_key_id = {};
    uint8_t my_ephemeral_pub[65] = {0};
    // True once ecdh_generate_ephemeral_keypair() has produced a live PSA
    // key that still needs destroying - either by handle_key_accepted() once
    // it's used, or by connect_to_bluetti()/stop_connection() if the
    // connection never gets that far.
    bool my_ephemeral_key_valid = false;

    // --- Command/response buffer (one request in flight at a time) ---
    uint8_t response_buf[256];
    size_t response_len = 0;
    bool response_ok = false;

    // Reassembly buffer for encrypted messages that span multiple BLE
    // notifications (see on_notification()). Reset to empty once a full
    // message has been handed off, or when a new connection starts.
    uint8_t rx_buf[320];
    size_t rx_len = 0;

    // Temporary characteristic-discovery scratch state (connecting only).
    struct DiscoveredChr { uint16_t def_handle; uint16_t val_handle; uint16_t uuid16; };
    static const int MAX_CHRS = 16;
    DiscoveredChr chrs[MAX_CHRS];
    int chr_count = 0;
};

static BluettiState bluettiState;

// Forward declarations - these functions call each other, so the compiler
// needs to know they exist before seeing the full bodies (C# doesn't need
// this because the compiler resolves the whole file/assembly up front).
static int gap_event_cb(struct ble_gap_event *event, void *arg);
static void on_notification(const uint8_t *data, size_t len);
static void notify_worker_task(void *param);
static bool send_raw(const uint8_t *data, size_t len);
static int chr_disc_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                       const struct ble_gatt_chr *chr, void *arg);
static int dsc_disc_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                       uint16_t chr_val_handle, const struct ble_gatt_dsc *dsc, void *arg);
static int subscribe_write_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                              struct ble_gatt_attr *attr, void *arg);
static int write_cmd_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                        struct ble_gatt_attr *attr, void *arg);
static int mtu_exchange_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                           uint16_t mtu, void *arg);

// Parses "AA:BB:CC:DD:EE:FF" into a ble_addr_t. BLE addresses are stored
// little-endian (val[0] is the LAST octet of the usual string form), so we
// reverse the order while parsing.
static bool parse_mac_address(const char *str, ble_addr_t *out)
{
    unsigned int bytes[6];
    if (sscanf(str, "%2x:%2x:%2x:%2x:%2x:%2x",
               &bytes[0], &bytes[1], &bytes[2], &bytes[3], &bytes[4], &bytes[5]) != 6) {
        return false;
    }
    out->type = BLE_ADDR_PUBLIC;
    for (int i = 0; i < 6; i++) {
        out->val[i] = (uint8_t)bytes[5 - i];
    }
    return true;
}

// Mirror of parse_mac_address(): formats a ble_addr_t back into
// "AA:BB:CC:DD:EE:FF", for logging.
//
// C# note: there's no string type here - the caller passes a buffer (>= 18
// bytes: 6 hex pairs + 5 colons + null terminator) to write into, similar in
// spirit to a `Span<char>` overload in .NET, but with no runtime bounds
// checking - sizing the buffer correctly is entirely on the caller.
static void format_mac_address(const ble_addr_t *addr, char *out, size_t out_cap)
{
    // addr->val[0] holds the LAST octet of the usual colon notation - see
    // parse_mac_address() above - so we walk val[] backwards to print in
    // the familiar AA:BB:CC:DD:EE:FF order.
    snprintf(out, out_cap, "%02X:%02X:%02X:%02X:%02X:%02X",
             addr->val[5], addr->val[4], addr->val[3],
             addr->val[2], addr->val[1], addr->val[0]);
}

// Logs one BLE advertisement seen during a scan (address, RSSI, name),
// whether or not it matches our target - handy for finding a station's real
// MAC address from the serial monitor: macOS/iOS apps only ever see a
// randomized per-app UUID, never the station's real BLE address, so a MAC
// copied from a phone/Mac scanner app is often useless here.
static void log_discovered_device(const struct ble_gap_disc_desc *disc)
{
    char addr_str[18];
    format_mac_address(&disc->addr, addr_str, sizeof(addr_str));

    // The advertisement payload is a sequence of Type-Length-Value records
    // (name, service UUIDs, etc). ble_hs_adv_parse_fields() parses them all
    // for us; we only care about the name here.
    struct ble_hs_adv_fields fields;
    memset(&fields, 0, sizeof(fields));
    ble_hs_adv_parse_fields(&fields, disc->data, disc->length_data);

    // fields.name points into the raw advertisement packet and is NOT
    // null-terminated (BLE uses length-prefixed fields, not C strings), so
    // it has to be copied + terminated before treating it as a C string.
    // Names are capped at 31 bytes by the BLE spec, so 32 bytes is enough.
    char name[32] = "(no name advertised)";
    if (fields.name != nullptr && fields.name_len > 0) {
        size_t copy_len = fields.name_len;
        if (copy_len >= sizeof(name)) {
            copy_len = sizeof(name) - 1;
        }
        memcpy(name, fields.name, copy_len);
        name[copy_len] = '\0';
    }

    // RSSI (dBm) is always negative; closer to 0 means a stronger/closer
    // signal (e.g. -40 is very close, -90 is weak/far away).
    ESP_LOGI(TAG, "  seen: %s  rssi=%d  name=\"%s\"",
             addr_str, (int)disc->rssi, name);
}

// -----------------------------------------------------------------------
// NimBLE host lifecycle callbacks.
// -----------------------------------------------------------------------
static void on_host_reset(int reason)
{
    ESP_LOGW(TAG, "NimBLE host reset, reason=%d", reason);
}

static void on_host_sync(void)
{
    // Prefer a public address if the controller has one.
    ble_hs_id_infer_auto(0, &bluettiState.own_addr_type);
    if (bluettiState.sem_sync) {
        xSemaphoreGive(bluettiState.sem_sync);
    }
}

static void nimble_host_task(void *param)
{
    ESP_LOGI(TAG, "NimBLE host task started");
    nimble_port_run(); // returns only when nimble_port_stop() is called
    nimble_port_freertos_deinit();
}

// -----------------------------------------------------------------------
// Runs on its own FreeRTOS task (with a large stack) so that decrypting a
// notification - AES, SHA-256, and especially ECDSA/ECDH on the P-256 curve
// - never runs on NimBLE's own host task, which only has a small, fixed
// stack (CONFIG_BT_NIMBLE_HOST_TASK_STACK_SIZE) sized for NimBLE's own
// needs. gap_event_cb() just copies notification bytes into a queue
// (cheap); this task blocks on that queue and does the real work.
//
// C# analogy: gap_event_cb() is like an event handler that should return
// fast, and this task is a background worker it hands off to via a queue -
// similar to not doing heavy work directly in a UI event handler and
// posting to a background thread/Channel<T> instead. Unlike .NET thread
// pool threads (1MB default stack), an RTOS task's stack is a small, fixed,
// hand-picked size - overflowing it silently corrupts memory instead of
// throwing an exception.
// -----------------------------------------------------------------------
static void notify_worker_task(void *param)
{
    NotifyItem item;
    for (;;) {
        // portMAX_DELAY = block forever until an item arrives; zero CPU use
        // while idle.
        if (xQueueReceive(bluettiState.notify_queue, &item, portMAX_DELAY) == pdTRUE) {
            on_notification(item.data, item.len);
        }
    }
}

// Initializes the NimBLE stack exactly once, no matter how many times
// connect_to_bluetti() is called.
static bool ensure_nimble_started(void)
{
    if (bluettiState.nimble_started) {
        return true;
    }

    if (!bluettiState.sem_sync) bluettiState.sem_sync = xSemaphoreCreateBinary();
    if (!bluettiState.sem_gap_step) bluettiState.sem_gap_step = xSemaphoreCreateBinary();
    if (!bluettiState.sem_handshake) bluettiState.sem_handshake = xSemaphoreCreateBinary();
    if (!bluettiState.sem_response) bluettiState.sem_response = xSemaphoreCreateBinary();
    if (!bluettiState.sem_disconnect) bluettiState.sem_disconnect = xSemaphoreCreateBinary();
    if (!bluettiState.mutex) bluettiState.mutex = xSemaphoreCreateMutex();

    // Depth 32: a full handshake message can arrive as ~8 fragments, and
    // the station retransmits the whole message if it doesn't hear back in
    // time - so the queue needs room for more than one message's worth of
    // fragments while notify_worker_task is still busy with an earlier one.
    if (!bluettiState.notify_queue) {
        bluettiState.notify_queue = xQueueCreate(32, sizeof(NotifyItem));
        if (!bluettiState.notify_queue) {
            ESP_LOGE(TAG, "ensure_nimble_started: failed to create notify queue");
            return false;
        }
    }

    // 12KB stack: comfortably more than P-256 ECDH/ECDSA plus our own
    // buffers need. Priority 10 (above the default app task priority of 1)
    // so this task is scheduled promptly when a notification arrives.
    static TaskHandle_t notify_task_handle = nullptr;
    if (!notify_task_handle) {
        BaseType_t task_ok = xTaskCreate(notify_worker_task, "bluetti_notify",
                                         12288, nullptr, 10, &notify_task_handle);
        if (task_ok != pdPASS) {
            ESP_LOGE(TAG, "ensure_nimble_started: failed to create notify worker task");
            return false;
        }
    }

    if (psa_crypto_init() != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_crypto_init failed");
        return false;
    }

    esp_err_t ret = (esp_err_t)nimble_port_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "nimble_port_init failed: %d", ret);
        return false;
    }

    ble_hs_cfg.reset_cb = on_host_reset;
    ble_hs_cfg.sync_cb = on_host_sync;
    // No BLE-level pairing/bonding here - Bluetti's encryption is a custom
    // application-layer protocol on top of a plain open BLE link, not
    // standard BLE security, so no bonding store is needed.

    nimble_port_freertos_init(nimble_host_task);

    // Wait for on_host_sync() before scanning/connecting.
    if (xSemaphoreTake(bluettiState.sem_sync, pdMS_TO_TICKS(5000)) != pdTRUE) {
        ESP_LOGE(TAG, "Timed out waiting for NimBLE host sync");
        return false;
    }

    bluettiState.nimble_started = true;
    return true;
}

// -----------------------------------------------------------------------
// Handles every BLE connection-lifecycle event: scanning, connecting,
// discovering, and incoming notifications.
//
// C# analogy: one event handler multiplexing several distinct events into a
// single switch, dispatched by event->type - that's how NimBLE's C API
// shapes what would be several separate event handlers/delegates in C#.
// -----------------------------------------------------------------------
static int gap_event_cb(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {

    case BLE_GAP_EVENT_DISC: {
        // Fires once per advertisement/scan-response packet - the same
        // physical device can trigger this multiple times per scan.
        //
        // Log every device seen (not just matches) - see
        // log_discovered_device() for why that's the most reliable way to
        // find a station's real MAC address.
        log_discovered_device(&event->disc);

        // Is this the station we're configured to connect to?
        if (bluettiState.have_target_addr &&
            memcmp(event->disc.addr.val, bluettiState.target_addr.val, 6) == 0) {
            ESP_LOGI(TAG, "Found target station, connecting...");
            ble_gap_disc_cancel();
            int rc = ble_gap_connect(bluettiState.own_addr_type, &event->disc.addr,
                                      10000 /* ms */, nullptr, gap_event_cb, nullptr);
            if (rc != 0) {
                ESP_LOGE(TAG, "ble_gap_connect failed: %d", rc);
                bluettiState.gap_step_ok = false;
                xSemaphoreGive(bluettiState.sem_gap_step);
            }
        }
        return 0;
    }

    case BLE_GAP_EVENT_DISC_COMPLETE: {
        // Scan window expired without finding the station.
        ESP_LOGW(TAG, "Scan finished without finding the station (reason=%d)",
                 event->disc_complete.reason);
        bluettiState.gap_step_ok = false;
        xSemaphoreGive(bluettiState.sem_gap_step);
        return 0;
    }

    case BLE_GAP_EVENT_CONNECT: {
        if (event->connect.status != 0) {
            ESP_LOGE(TAG, "Connection failed, status=%d", event->connect.status);
            bluettiState.gap_step_ok = false;
            xSemaphoreGive(bluettiState.sem_gap_step);
            return 0;
        }
        ESP_LOGI(TAG, "Connected, discovering characteristics...");
        bluettiState.conn_handle = event->connect.conn_handle;
        bluettiState.chr_count = 0;

        // Request a bigger ATT_MTU than the default 23 bytes (20 usable
        // payload) - most handshake/command messages don't fit in that.
        // Fire-and-forget: mtu_exchange_cb() just logs the result, while
        // characteristic discovery proceeds in parallel below.
        int mtu_rc = ble_gattc_exchange_mtu(bluettiState.conn_handle, mtu_exchange_cb, nullptr);
        if (mtu_rc != 0) {
            ESP_LOGW(TAG, "ble_gattc_exchange_mtu failed to start: %d", mtu_rc);
        }

        int rc = ble_gattc_disc_all_chrs(bluettiState.conn_handle, 0x0001, 0xFFFF, chr_disc_cb, nullptr);
        if (rc != 0) {
            ESP_LOGE(TAG, "ble_gattc_disc_all_chrs failed: %d", rc);
            bluettiState.gap_step_ok = false;
            xSemaphoreGive(bluettiState.sem_gap_step);
        }
        return 0;
    }

    case BLE_GAP_EVENT_DISCONNECT: {
        ESP_LOGW(TAG, "Disconnected (reason=%d)", event->disconnect.reason);
        bluettiState.conn_handle = BLE_HS_CONN_HANDLE_NONE;
        // Wakes up stop_connection(), which waits for this rather than
        // assuming ble_gap_terminate() (an async request) has actually
        // finished tearing down the link by the time it returns.
        xSemaphoreGive(bluettiState.sem_disconnect);
        return 0;
    }

    case BLE_GAP_EVENT_NOTIFY_RX: {
        // Runs on NimBLE's small-stack host task - copy the bytes and hand
        // off to notify_worker_task() via a queue rather than processing
        // here (see that function's comment).
        uint16_t len = OS_MBUF_PKTLEN(event->notify_rx.om);
        NotifyItem item;
        if (len > sizeof(item.data)) {
            ESP_LOGE(TAG, "Notification too large (%u bytes), dropping", (unsigned)len);
            return 0;
        }
        os_mbuf_copydata(event->notify_rx.om, 0, len, item.data);
        item.len = len;

        // Non-blocking send: if the queue is ever full, drop the
        // notification and log it rather than stalling NimBLE's host task
        // waiting for space (which would also delay connection
        // supervision, etc).
        if (xQueueSend(bluettiState.notify_queue, &item, 0) != pdTRUE) {
            ESP_LOGE(TAG, "notify queue full, dropping notification");
        }
        return 0;
    }

    default:
        return 0;
    }
}

// Reports the outcome of the MTU exchange requested in gap_event_cb's
// BLE_GAP_EVENT_CONNECT handler. Purely informational - ble_att_mtu(conn_handle)
// can be checked at any time afterward if code needs the actual value.
static int mtu_exchange_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                           uint16_t mtu, void *arg)
{
    (void)arg;
    if (error->status != 0) {
        ESP_LOGW(TAG, "MTU exchange failed (status=%d) - staying on the default 23-byte MTU",
                 error->status);
    } else {
        ESP_LOGI(TAG, "MTU negotiated: %u bytes (%u usable payload bytes per ATT operation)",
                 (unsigned)mtu, (unsigned)(mtu - 3));
    }
    (void)conn_handle;
    return 0;
}

// Called once per discovered characteristic, then once more with
// error->status == BLE_HS_EDONE when discovery is complete.
static int chr_disc_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                       const struct ble_gatt_chr *chr, void *arg)
{
    (void)conn_handle;
    (void)arg;

    if (error->status == 0 && chr != nullptr) {
        if (bluettiState.chr_count < BluettiState::MAX_CHRS) {
            uint16_t uuid16 = 0;
            if (chr->uuid.u.type == BLE_UUID_TYPE_16) {
                uuid16 = ((const ble_uuid16_t *)&chr->uuid)->value;
            }
            bluettiState.chrs[bluettiState.chr_count].def_handle = chr->def_handle;
            bluettiState.chrs[bluettiState.chr_count].val_handle = chr->val_handle;
            bluettiState.chrs[bluettiState.chr_count].uuid16 = uuid16;
            bluettiState.chr_count++;
        }
        return 0;
    }

    if (error->status != BLE_HS_EDONE) {
        ESP_LOGE(TAG, "Characteristic discovery error: %d", error->status);
        bluettiState.gap_step_ok = false;
        xSemaphoreGive(bluettiState.sem_gap_step);
        return 0;
    }

    // Discovery complete - find our write/notify characteristics.
    uint16_t write_handle = 0, notify_val = 0, notify_def = 0;
    int notify_index = -1;
    for (int i = 0; i < bluettiState.chr_count; i++) {
        if (bluettiState.chrs[i].uuid16 == BLUETTI_WRITE_UUID16) {
            write_handle = bluettiState.chrs[i].val_handle;
        } else if (bluettiState.chrs[i].uuid16 == BLUETTI_NOTIFY_UUID16) {
            notify_val = bluettiState.chrs[i].val_handle;
            notify_def = bluettiState.chrs[i].def_handle;
            notify_index = i;
        }
    }

    if (write_handle == 0 || notify_val == 0) {
        ESP_LOGE(TAG, "Could not find Bluetti write/notify characteristics "
                       "(found %d characteristics total)", bluettiState.chr_count);
        bluettiState.gap_step_ok = false;
        xSemaphoreGive(bluettiState.sem_gap_step);
        return 0;
    }

    bluettiState.write_val_handle = write_handle;
    bluettiState.notify_val_handle = notify_val;
    bluettiState.notify_def_handle = notify_def;

    // Figure out an upper bound for descriptor discovery: the start handle
    // of whichever *other* discovered characteristic comes right after this
    // one (by def_handle), or the top of the handle range if it's last.
    uint16_t end_handle = 0xFFFF;
    for (int i = 0; i < bluettiState.chr_count; i++) {
        if (i == notify_index) continue;
        if (bluettiState.chrs[i].def_handle > notify_def && bluettiState.chrs[i].def_handle - 1 < end_handle) {
            end_handle = bluettiState.chrs[i].def_handle - 1;
        }
    }

    ESP_LOGI(TAG, "Found write=0x%04x notify=0x%04x, discovering CCCD in [0x%04x, 0x%04x]",
             write_handle, notify_val, (unsigned)(notify_val + 1), end_handle);

    int rc = ble_gattc_disc_all_dscs(bluettiState.conn_handle, notify_val, end_handle, dsc_disc_cb, nullptr);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gattc_disc_all_dscs failed: %d", rc);
        bluettiState.gap_step_ok = false;
        xSemaphoreGive(bluettiState.sem_gap_step);
    }
    return 0;
}

// Fires after we write the CCCD to subscribe to notifications.
static int subscribe_write_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                              struct ble_gatt_attr *attr, void *arg)
{
    (void)conn_handle; (void)attr; (void)arg;
    if (error->status != 0) {
        ESP_LOGE(TAG, "CCCD write failed: %d", error->status);
        bluettiState.gap_step_ok = false;
    } else {
        ESP_LOGI(TAG, "Subscribed to notifications");
        bluettiState.gap_step_ok = true;
    }
    xSemaphoreGive(bluettiState.sem_gap_step);
    return 0;
}

static int dsc_disc_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                       uint16_t chr_val_handle, const struct ble_gatt_dsc *dsc, void *arg)
{
    (void)conn_handle; (void)chr_val_handle; (void)arg;

    if (error->status == 0 && dsc != nullptr) {
        // 0x2902 = "Client Characteristic Configuration Descriptor" (CCCD) -
        // writing 0x0001 to it turns on notifications.
        if (dsc->uuid.u.type == BLE_UUID_TYPE_16 &&
            ((const ble_uuid16_t *)&dsc->uuid)->value == 0x2902) {
            bluettiState.cccd_handle = dsc->handle;
        }
        return 0;
    }

    if (error->status != BLE_HS_EDONE) {
        ESP_LOGE(TAG, "Descriptor discovery error: %d", error->status);
        bluettiState.gap_step_ok = false;
        xSemaphoreGive(bluettiState.sem_gap_step);
        return 0;
    }

    if (bluettiState.cccd_handle == 0) {
        ESP_LOGE(TAG, "Could not find the notify characteristic's CCCD");
        bluettiState.gap_step_ok = false;
        xSemaphoreGive(bluettiState.sem_gap_step);
        return 0;
    }

    static uint8_t enable_notify[2] = {0x01, 0x00};
    int rc = ble_gattc_write_flat(bluettiState.conn_handle, bluettiState.cccd_handle,
                                   enable_notify, sizeof(enable_notify),
                                   subscribe_write_cb, nullptr);
    if (rc != 0) {
        ESP_LOGE(TAG, "Writing CCCD failed: %d", rc);
        bluettiState.gap_step_ok = false;
        xSemaphoreGive(bluettiState.sem_gap_step);
    }
    return 0;
}

// Fires once the station acknowledges (or rejects) a write. Nothing to do
// on success; a failure is worth logging since it means the station didn't
// even accept the write at the BLE layer.
static int write_cmd_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                        struct ble_gatt_attr *attr, void *arg)
{
    (void)conn_handle; (void)attr; (void)arg;
    if (error->status != 0) {
        ESP_LOGE(TAG, "send_raw: write was not acknowledged by the station, status=%d", error->status);
    }
    return 0;
}

// Writes raw bytes to the station's WRITE characteristic using an
// acknowledged GATT "Write Request" (ble_gattc_write_flat) rather than an
// unacknowledged "Write Command" - this station's firmware only accepts
// application-layer data delivered the acknowledged way.
static bool send_raw(const uint8_t *data, size_t len)
{
    if (bluettiState.conn_handle == BLE_HS_CONN_HANDLE_NONE) {
        return false;
    }
    int rc = ble_gattc_write_flat(bluettiState.conn_handle, bluettiState.write_val_handle, data, len, write_cmd_cb, nullptr);
    if (rc != 0) {
        ESP_LOGE(TAG, "send_raw: write failed, rc=%d", rc);
        return false;
    }
    return true;
}

// =============================================================================
// SECTION 6: Handshake message handlers
// Direct ports of msg_challenge/msg_peer_pubkey/msg_key_accepted from
// bluetooth/encryption.py.
// =============================================================================

// Builds a "pre-key-exchange" frame (magic + type + reserved + payload +
// checksum) and sends it unencrypted.
static bool send_handshake_message(uint8_t type, uint8_t reserved,
                                   const uint8_t *payload, size_t payload_len)
{
    uint8_t body[200];
    if (2 + payload_len > sizeof(body)) return false;
    body[0] = type;
    body[1] = reserved;
    memcpy(body + 2, payload, payload_len);
    size_t body_len = 2 + payload_len;

    uint8_t msg[210];
    memcpy(msg, KEX_MAGIC, 2);
    memcpy(msg + 2, body, body_len);
    body_checksum(body, body_len, msg + 2 + body_len);
    size_t msg_len = 2 + body_len + 2;

    return send_raw(msg, msg_len);
}

// Same framing as above, but AES-encrypts the message first (used once
// we're in the "unsecure" phase - see msg_peer_pubkey in the Python source).
static bool send_encrypted_handshake_message(uint8_t type, uint8_t reserved,
                                             const uint8_t *payload, size_t payload_len,
                                             const uint8_t *key16, const uint8_t *iv16)
{
    uint8_t body[200];
    if (2 + payload_len > sizeof(body)) return false;
    body[0] = type;
    body[1] = reserved;
    memcpy(body + 2, payload, payload_len);
    size_t body_len = 2 + payload_len;

    uint8_t msg[210];
    memcpy(msg, KEX_MAGIC, 2);
    memcpy(msg + 2, body, body_len);
    body_checksum(body, body_len, msg + 2 + body_len);
    size_t msg_len = 2 + body_len + 2;

    uint8_t encrypted[256];
    size_t encrypted_len = 0;
    // Always called with the 16-byte unsecure_aes_key - handshake-phase
    // traffic is always AES-128.
    if (!aes_cbc_encrypt(msg, msg_len, key16, 16, iv16, encrypted, sizeof(encrypted), &encrypted_len)) {
        return false;
    }
    return send_raw(encrypted, encrypted_len);
}

// STATION -> US: "here's a random challenge, derive the bootstrap key".
// `payload` is the 4-byte challenge data (Message.data in Python).
static void handle_challenge(const uint8_t *payload, size_t payload_len)
{
    if (payload_len != 4) {
        ESP_LOGE(TAG, "handle_challenge: unexpected length %u", (unsigned)payload_len);
        return;
    }

    // unsecure_aes_iv = md5(reversed(challenge_bytes))
    uint8_t reversed[4] = {payload[3], payload[2], payload[1], payload[0]};
    md5(reversed, 4, bluettiState.unsecure_aes_iv);

    // unsecure_aes_key = unsecure_aes_iv XOR LOCAL_AES_KEY
    for (int i = 0; i < 16; i++) {
        bluettiState.unsecure_aes_key[i] = bluettiState.unsecure_aes_iv[i] ^ LOCAL_AES_KEY[i];
    }

    bluettiState.stage = HS_GOT_UNSECURE_KEY;

    // Reply (unencrypted): body = [0x02, 0x04] + iv[8:12]
    uint8_t reply_payload[4];
    memcpy(reply_payload, bluettiState.unsecure_aes_iv + 8, 4);
    send_handshake_message(0x02, 0x04, reply_payload, sizeof(reply_payload));
}

// STATION -> US: encrypted message containing the station's ephemeral
// public key + a signature proving it's a genuine Bluetti station.
// `payload` is the 128-byte Message.data (64 bytes pubkey + 64 bytes sig).
static void handle_peer_pubkey(const uint8_t *payload, size_t payload_len)
{
    if (payload_len != 128) {
        ESP_LOGE(TAG, "handle_peer_pubkey: unexpected length %u", (unsigned)payload_len);
        return;
    }

    // Logs how long each crypto step takes (microseconds since boot) -
    // useful for spotting whether the handshake is slow enough for the
    // station to time out.
    int64_t t_start = esp_timer_get_time();

    const uint8_t *peer_pub_xy = payload;      // 64 bytes: X || Y
    const uint8_t *signature = payload + 64;   // 64 bytes: r || s

    // The station signs (peer_pub_xy || unsecure_aes_iv), so we need to
    // reconstruct that exact byte string before hashing/verifying.
    uint8_t signed_data[64 + 16];
    memcpy(signed_data, peer_pub_xy, 64);
    memcpy(signed_data + 64, bluettiState.unsecure_aes_iv, 16);

    uint8_t digest[32];
    sha256(signed_data, sizeof(signed_data), digest);

    int64_t t_after_sha1 = esp_timer_get_time();

    // vTaskDelay(1) here and after the next two steps: this runs on
    // notify_worker_task, and each ECDSA/ECDH step below takes long enough
    // (hundreds of ms) that running them back-to-back with no yield can
    // starve the FreeRTOS idle task on this core - which is what feeds the
    // Task Watchdog Timer. A 1-tick yield costs nothing next to the crypto
    // time but keeps the watchdog fed. (No equivalent concern in C# - the
    // OS scheduler preempts threads for you.)
    vTaskDelay(1);

    if (!ecdsa_verify_with_k2(digest, signature)) {
        ESP_LOGE(TAG, "handle_peer_pubkey: signature verification FAILED - "
                       "refusing to continue the handshake");
        return;
    }

    int64_t t_after_verify = esp_timer_get_time();
    vTaskDelay(1);

    bluettiState.peer_pubkey[0] = 0x04;
    memcpy(bluettiState.peer_pubkey + 1, peer_pub_xy, 64);

    // Our ephemeral keypair is generated ahead of time in
    // connect_to_bluetti() (it doesn't depend on anything the station
    // sends), so there's nothing to do here except confirm it exists.
    if (!bluettiState.my_ephemeral_key_valid) {
        ESP_LOGE(TAG, "handle_peer_pubkey: no pre-generated ephemeral keypair available");
        return;
    }

    // Sign (my_pubkey_xy || unsecure_aes_iv) with our long-term key.
    uint8_t to_sign[64 + 16];
    memcpy(to_sign, bluettiState.my_ephemeral_pub + 1, 64); // skip the leading 0x04
    memcpy(to_sign + 64, bluettiState.unsecure_aes_iv, 16);

    uint8_t to_sign_digest[32];
    sha256(to_sign, sizeof(to_sign), to_sign_digest);

    uint8_t signature_out[64];
    if (!ecdsa_sign_with_l1(to_sign_digest, signature_out)) {
        ESP_LOGE(TAG, "handle_peer_pubkey: failed to sign our ephemeral pubkey");
        return;
    }

    int64_t t_after_sign = esp_timer_get_time();

    bluettiState.stage = HS_GOT_PEER_PUBKEY;

    // Reply, ENCRYPTED under the unsecure key/iv: body = [0x05, 0x80] +
    // my_pubkey_xy(64) + signature(64).
    uint8_t reply_payload[128];
    memcpy(reply_payload, bluettiState.my_ephemeral_pub + 1, 64);
    memcpy(reply_payload + 64, signature_out, 64);

    send_encrypted_handshake_message(0x05, 0x80, reply_payload, sizeof(reply_payload),
                                      bluettiState.unsecure_aes_key, bluettiState.unsecure_aes_iv);

    int64_t t_end = esp_timer_get_time();
    ESP_LOGI(TAG, "handle_peer_pubkey timing (us): sha1=%lld verify=%lld sign=%lld send=%lld TOTAL=%lld",
             (long long)(t_after_sha1 - t_start),
             (long long)(t_after_verify - t_after_sha1),
             (long long)(t_after_sign - t_after_verify),
             (long long)(t_end - t_after_sign),
             (long long)(t_end - t_start));
}

// STATION -> US: encrypted confirmation that our key exchange was accepted.
// `payload` is 1 byte, must be 0x00.
static void handle_key_accepted(const uint8_t *payload, size_t payload_len)
{
    if (payload_len != 1 || payload[0] != 0) {
        ESP_LOGE(TAG, "handle_key_accepted: unexpected payload");
        return;
    }

    uint8_t shared32[32];
    if (!ecdh_compute_shared(bluettiState.my_ephemeral_priv_key_id, bluettiState.peer_pubkey, shared32)) {
        ESP_LOGE(TAG, "handle_key_accepted: ECDH shared-secret computation failed");
        return;
    }
    memcpy(bluettiState.secure_aes_key, shared32, 32); // full 32 bytes used as an AES-256 key - see the field's own comment

    psa_destroy_key(bluettiState.my_ephemeral_priv_key_id); // no longer needed
    bluettiState.my_ephemeral_key_valid = false; // matches the speculative generation in connect_to_bluetti()

    bluettiState.stage = HS_READY;
    bluettiState.handshake_ok = true;
    xSemaphoreGive(bluettiState.sem_handshake);
    ESP_LOGI(TAG, "Encryption handshake complete - ready to send commands");
}

// Handles one COMPLETE unencrypted handshake frame (CHALLENGE or
// CHALLENGE_ACCEPTED). These are always small (well under 20 bytes) and
// always arrive whole in a single BLE notification in practice, which is
// why on_notification() below hands them here directly with no reassembly
// step.
static void dispatch_unencrypted_handshake_frame(const uint8_t *data, size_t len)
{
    const uint8_t *body = data + 2;
    size_t body_len = len - 4; // strip 2-byte magic + 2-byte checksum
    uint8_t type = body[0];
    const uint8_t *payload = body + 2;
    size_t payload_len = body_len - 2;

    if (type == MSG_CHALLENGE) {
        handle_challenge(payload, payload_len);
    } else if (type == MSG_CHALLENGE_ACCEPTED) {
        ESP_LOGI(TAG, "Challenge accepted by station");
    } else {
        ESP_LOGW(TAG, "Unexpected unencrypted handshake message type=%d", type);
    }
}

// Handles one COMPLETE encrypted message - either a mid-handshake message
// (PEER_PUBKEY / PUBKEY_ACCEPTED) or, once HS_READY, a normal Modbus
// command response. "Complete" here means on_notification() has already
// reassembled every BLE-notification fragment it belongs to (see the big
// comment there) - `data`/`len` cover the WHOLE encrypted message, ready to
// feed straight into aes_cbc_decrypt().
static void dispatch_encrypted_message(const uint8_t *data, size_t len)
{
    if (bluettiState.stage == HS_READY) {
        // Normal, already-encrypted Modbus response. secure_aes_key is the
        // FULL 32-byte raw ECDH shared secret used as-is - see the comment
        // on BluettiState::secure_aes_key for why this is AES-256, not
        // AES-128 (despite unsecure_aes_key, used below, being AES-128).
        uint8_t plain[256];
        size_t plain_len = 0;
        if (!aes_cbc_decrypt(data, len, bluettiState.secure_aes_key, sizeof(bluettiState.secure_aes_key), nullptr, plain, sizeof(plain), &plain_len)) {
            ESP_LOGE(TAG, "dispatch_encrypted_message: failed to decrypt command response");
            return;
        }
        memcpy(bluettiState.response_buf, plain, plain_len);
        bluettiState.response_len = plain_len;
        bluettiState.response_ok = true;
        xSemaphoreGive(bluettiState.sem_response);
        return;
    }

    // Otherwise we must be mid-handshake, waiting on an *encrypted*
    // handshake message (PEER_PUBKEY or PUBKEY_ACCEPTED), encrypted under
    // the "unsecure" bootstrap key/iv derived from the initial challenge.
    uint8_t plain[256];
    size_t plain_len = 0;
    if (!aes_cbc_decrypt(data, len, bluettiState.unsecure_aes_key, sizeof(bluettiState.unsecure_aes_key), bluettiState.unsecure_aes_iv, plain, sizeof(plain), &plain_len)) {
        ESP_LOGE(TAG, "dispatch_encrypted_message: failed to decrypt handshake message");
        return;
    }
    if (plain_len < 4 || plain[0] != KEX_MAGIC[0] || plain[1] != KEX_MAGIC[1]) {
        ESP_LOGE(TAG, "dispatch_encrypted_message: decrypted handshake message missing magic bytes");
        return;
    }

    const uint8_t *body = plain + 2;
    size_t body_len = plain_len - 4;
    uint8_t type = body[0];
    const uint8_t *payload = body + 2;
    size_t payload_len = body_len - 2;

    if (type == MSG_PEER_PUBKEY) {
        handle_peer_pubkey(payload, payload_len);
    } else if (type == MSG_PUBKEY_ACCEPTED) {
        handle_key_accepted(payload, payload_len);
    } else {
        ESP_LOGW(TAG, "Unexpected encrypted handshake message type=%d", type);
    }
}

// Called from the BLE notification callback for every incoming RAW
// notification PACKET - which, importantly, may only be a FRAGMENT of a
// larger logical message, not the whole thing.
//
// WHY FRAGMENTS HAPPEN: the default BLE ATT MTU is 23 bytes (20 usable
// payload bytes). Any encrypted message longer than that - which is most of
// them, since AES-CBC pads to a 16-byte multiple plus a length header -
// gets split by the STATION into several back-to-back notifications, and
// NimBLE delivers each as a separate callback with no automatic reassembly.
//
// HOW REASSEMBLY WORKS: aes_cbc_encrypt() (SECTION 3) always writes a
// 2-byte "declared plaintext length" as the very first thing in the
// message, UNENCRYPTED. So as soon as those first 2 bytes arrive, we can
// compute the exact total wire length (header + ciphertext, padded to a
// 16-byte multiple) and know how many more bytes to wait for before
// attempting to decrypt.
static void on_notification(const uint8_t *data, size_t len)
{
    if (!bluettiState.use_encryption) {
        // Unencrypted devices: notifications are always plain Modbus
        // responses, no handshake at all. (Not reassembled - this
        // project's read-one-register-at-a-time usage keeps these small
        // enough to always fit in a single notification.)
        if (len > sizeof(bluettiState.response_buf)) len = sizeof(bluettiState.response_buf);
        memcpy(bluettiState.response_buf, data, len);
        bluettiState.response_len = len;
        bluettiState.response_ok = true;
        xSemaphoreGive(bluettiState.sem_response);
        return;
    }

    // Unencrypted handshake frames (CHALLENGE / CHALLENGE_ACCEPTED) are
    // small and always arrive whole - recognise and handle them directly,
    // without going through the reassembly buffer at all. We only take
    // this branch when we're not already midway through reassembling
    // something else (rx_len == 0), so a coincidental 0x2A 0x2A byte pair
    // inside an in-progress ciphertext can't be misread as the start of a
    // new unencrypted frame.
    if (bluettiState.rx_len == 0 && len >= 4 && data[0] == KEX_MAGIC[0] && data[1] == KEX_MAGIC[1]) {
        dispatch_unencrypted_handshake_frame(data, len);
        return;
    }

    // Otherwise, accumulate this fragment into the reassembly buffer.
    if (bluettiState.rx_len + len > sizeof(bluettiState.rx_buf)) {
        ESP_LOGE(TAG, "on_notification: reassembly buffer overflow, dropping in-progress message");
        bluettiState.rx_len = 0;
        return;
    }
    memcpy(bluettiState.rx_buf + bluettiState.rx_len, data, len);
    bluettiState.rx_len += len;

    // header_len mirrors the same iv16-null-or-not choice that
    // dispatch_encrypted_message() will make when it calls
    // aes_cbc_decrypt(): mid-handshake messages use an explicit IV (2-byte
    // header, no embedded seed); once HS_READY, normal traffic uses a
    // random per-message IV, which needs a 4-byte seed embedded right
    // after the 2-byte length (6-byte header total). See aes_cbc_decrypt()
    // in SECTION 3 for the full explanation of both formats.
    size_t header_len = (bluettiState.stage == HS_READY) ? 6 : 2;
    if (bluettiState.rx_len < header_len) {
        return; // haven't even received the full header yet - wait for more
    }

    // The 2-byte declared length is always the first thing in the buffer,
    // in both header formats, and is never encrypted - safe to read now.
    uint16_t declared_plain_len = ((uint16_t)bluettiState.rx_buf[0] << 8) | bluettiState.rx_buf[1];
    size_t padded_cipher_len = ((declared_plain_len + 15) / 16) * 16;
    if (padded_cipher_len == 0) padded_cipher_len = 16; // AES-CBC needs >= 1 block, same rule as aes_cbc_encrypt()
    size_t expected_total_len = header_len + padded_cipher_len;

    if (expected_total_len > sizeof(bluettiState.rx_buf)) {
        ESP_LOGE(TAG, "on_notification: declared message length looks bogus (%u), dropping",
                 (unsigned)declared_plain_len);
        bluettiState.rx_len = 0;
        return;
    }

    if (bluettiState.rx_len < expected_total_len) {
        // More fragments still to come - the BLE stack will call us again
        // with the next notification. Nothing else to do right now.
        return;
    }

    // We have every byte of the message - hand the complete thing off for
    // decryption, then reset the buffer so the next message starts fresh.
    dispatch_encrypted_message(bluettiState.rx_buf, expected_total_len);
    bluettiState.rx_len = 0;
}

// =============================================================================
// SECTION 7: Modbus-style register read commands
// =============================================================================

// Builds an 8-byte "read holding register(s)" command:
// [address=1][function=3][addr_hi][addr_lo][qty_hi][qty_lo][crc_lo][crc_hi]
static void build_read_command(uint16_t address, uint16_t quantity, uint8_t out[8])
{
    out[0] = 0x01;
    out[1] = MODBUS_READ_FUNCTION;
    out[2] = (uint8_t)(address >> 8);
    out[3] = (uint8_t)(address & 0xFF);
    out[4] = (uint8_t)(quantity >> 8);
    out[5] = (uint8_t)(quantity & 0xFF);
    uint16_t crc = modbus_crc16(out, 6);
    out[6] = (uint8_t)(crc & 0xFF);        // CRC is sent low-byte first
    out[7] = (uint8_t)((crc >> 8) & 0xFF);
}

// Sends one register-read command and waits for the corresponding response,
// returning just the data payload (quantity * 2 bytes). Returns true on
// success (valid CRC, matching function code), false on timeout/error.
static bool read_register(uint16_t address, uint16_t quantity,
                          uint8_t *out_data, size_t out_cap, size_t *out_len)
{
    uint8_t cmd[8];
    build_read_command(address, quantity, cmd);

    bluettiState.response_ok = false;
    xSemaphoreTake(bluettiState.sem_response, 0); // drain any stale signal

    bool sent;
    if (bluettiState.use_encryption) {
        uint8_t encrypted[64];
        size_t encrypted_len = 0;
        if (!aes_cbc_encrypt(cmd, sizeof(cmd), bluettiState.secure_aes_key, sizeof(bluettiState.secure_aes_key), nullptr,
                             encrypted, sizeof(encrypted), &encrypted_len)) {
            return false;
        }
        sent = send_raw(encrypted, encrypted_len);
    } else {
        sent = send_raw(cmd, sizeof(cmd));
    }
    if (!sent) return false;

    // Give the station a few seconds to answer (matches the 5s per-command
    // timeout used by the Python reference implementation).
    if (xSemaphoreTake(bluettiState.sem_response, pdMS_TO_TICKS(5000)) != pdTRUE) {
        ESP_LOGW(TAG, "read_register(0x%04x): timed out waiting for response", address);
        return false;
    }
    if (!bluettiState.response_ok) return false;

    const uint8_t *resp = bluettiState.response_buf;
    size_t resp_len = bluettiState.response_len;

    // Expect: [addr][func][byte_count][data...][crc_lo][crc_hi]
    size_t expected_len = 3 + (size_t)quantity * 2 + 2;
    if (resp_len != expected_len) {
        ESP_LOGW(TAG, "read_register(0x%04x): unexpected response length %u (wanted %u)",
                 address, (unsigned)resp_len, (unsigned)expected_len);
        return false;
    }

    uint16_t crc = modbus_crc16(resp, resp_len - 2);
    uint16_t crc_received = resp[resp_len - 2] | ((uint16_t)resp[resp_len - 1] << 8);
    if (crc != crc_received) {
        ESP_LOGW(TAG, "read_register(0x%04x): CRC mismatch", address);
        return false;
    }
    if (resp[1] != MODBUS_READ_FUNCTION) {
        ESP_LOGW(TAG, "read_register(0x%04x): station returned an error/exception response", address);
        return false;
    }

    size_t data_len = (size_t)quantity * 2;
    if (data_len > out_cap) return false;
    memcpy(out_data, resp + 3, data_len);
    *out_len = data_len;
    return true;
}

// Builds an 8-byte "write single register" command:
// [address=1][function=6][reg_hi][reg_lo][value_hi][value_lo][crc_lo][crc_hi]
static void build_write_command(uint16_t address, uint16_t value, uint8_t out[8])
{
    out[0] = 0x01;
    out[1] = MODBUS_WRITE_FUNCTION;
    out[2] = (uint8_t)(address >> 8);
    out[3] = (uint8_t)(address & 0xFF);
    out[4] = (uint8_t)(value >> 8);
    out[5] = (uint8_t)(value & 0xFF);
    uint16_t crc = modbus_crc16(out, 6);
    out[6] = (uint8_t)(crc & 0xFF);        // CRC is sent low-byte first
    out[7] = (uint8_t)((crc >> 8) & 0xFF);
}

// Sends one "write single register" command and waits for the station to
// echo it back - the standard Modbus confirmation for function code 6 is a
// byte-for-byte copy of the request. Returns true only if that exact echo
// arrives (which also implicitly confirms the CRC and function code, since
// any of those being wrong would make the echo not match what we sent).
//
// CAVEAT: unlike read_register() above, this has no working reference to
// verify against - bluetti-bt-lib's device_writer.py explicitly refuses to
// write anything when encryption is enabled ("Encryption on writes is not
// yet supported"). This implementation is a reasoned extrapolation - writes
// use the exact same Modbus framing + AES-CBC transport that reads already
// use successfully - not a verified port. Treat the first real write as a
// first test, not a known-working feature.
static bool write_register(uint16_t address, uint16_t value)
{
    uint8_t cmd[8];
    build_write_command(address, value, cmd);

    bluettiState.response_ok = false;
    xSemaphoreTake(bluettiState.sem_response, 0); // drain any stale signal

    bool sent;
    if (bluettiState.use_encryption) {
        uint8_t encrypted[64];
        size_t encrypted_len = 0;
        if (!aes_cbc_encrypt(cmd, sizeof(cmd), bluettiState.secure_aes_key, sizeof(bluettiState.secure_aes_key), nullptr,
                             encrypted, sizeof(encrypted), &encrypted_len)) {
            return false;
        }
        sent = send_raw(encrypted, encrypted_len);
    } else {
        sent = send_raw(cmd, sizeof(cmd));
    }
    if (!sent) return false;

    if (xSemaphoreTake(bluettiState.sem_response, pdMS_TO_TICKS(5000)) != pdTRUE) {
        ESP_LOGW(TAG, "write_register(0x%04x): timed out waiting for response", address);
        return false;
    }
    if (!bluettiState.response_ok) return false;

    const uint8_t *resp = bluettiState.response_buf;
    size_t resp_len = bluettiState.response_len;

    if (resp_len != sizeof(cmd) || memcmp(resp, cmd, sizeof(cmd)) != 0) {
        ESP_LOGW(TAG, "write_register(0x%04x): response did not echo the request "
                       "(len=%u) - station may have rejected the write or this isn't "
                       "how it wants encrypted writes framed", address, (unsigned)resp_len);
        return false;
    }
    return true;
}

// Reads a single 16-bit register and returns it as a plain integer.
static bool read_u16(uint16_t address, uint16_t *out_value)
{
    uint8_t data[2];
    size_t len = 0;
    if (!read_register(address, 1, data, sizeof(data), &len) || len != 2) {
        return false;
    }
    *out_value = ((uint16_t)data[0] << 8) | data[1];
    return true;
}

// Reads the device type/model string (e.g. "AC180P") from REG_DEVICE_TYPE.
// Unlike every other register in this file, this one isn't a number - it's
// a raw ASCII string packed into REG_DEVICE_TYPE_WORDS 16-bit words, with
// each adjacent byte pair swapped on the wire (the station's own encoding
// quirk for this field, confirmed against bluetti-bt-lib's SwapStringField -
// not something we get to choose). Shorter model names are right-padded
// with zero bytes, so the result is stopped at the first null.
static bool read_device_type(char *out, size_t out_cap)
{
    uint8_t raw[REG_DEVICE_TYPE_WORDS * 2];
    size_t len = 0;
    if (!read_register(REG_DEVICE_TYPE, REG_DEVICE_TYPE_WORDS, raw, sizeof(raw), &len)) {
        return false;
    }

    // Swap every adjacent byte pair (raw[0]<->raw[1], raw[2]<->raw[3], ...)
    // to undo the station's on-the-wire byte order for this field.
    for (size_t i = 0; i + 1 < len; i += 2) {
        uint8_t tmp = raw[i];
        raw[i] = raw[i + 1];
        raw[i + 1] = tmp;
    }

    size_t copy_len = (len < out_cap) ? len : out_cap - 1;
    size_t out_i = 0;
    for (; out_i < copy_len && raw[out_i] != '\0'; out_i++) {
        out[out_i] = (char)raw[out_i];
    }
    out[out_i] = '\0';
    return true;
}

// =============================================================================
// SECTION 8: Public API (see bluetti_ble.h for the "how to use this" docs)
// =============================================================================

bool connect_to_bluetti(const char *mac_address, bool use_encryption)
{
    if (!ensure_nimble_started()) {
        ESP_LOGE(TAG, "connect_to_bluetti: failed to start NimBLE host");
        return false;
    }

    if (!parse_mac_address(mac_address, &bluettiState.target_addr)) {
        ESP_LOGE(TAG, "connect_to_bluetti: invalid MAC address '%s' "
                       "(expected format AA:BB:CC:DD:EE:FF)", mac_address);
        return false;
    }
    bluettiState.have_target_addr = true;
    bluettiState.use_encryption = use_encryption;
    bluettiState.stage = HS_NOT_STARTED;
    bluettiState.handshake_ok = false;
    bluettiState.gap_step_ok = false;
    bluettiState.cccd_handle = 0;
    bluettiState.rx_len = 0; // discard any partially-reassembled message from a previous attempt

    // Generate OUR ephemeral ECDH keypair now, rather than waiting until
    // handle_peer_pubkey() needs it - it's random and doesn't depend on
    // anything the station sends, so generating it here overlaps it with
    // the next few seconds of scanning/connecting instead of adding to the
    // handshake's critical path.
    //
    // If a previous attempt generated a keypair that never got used (e.g.
    // the connection failed before the handshake got this far), destroy it
    // first - PSA has a limited number of key slots, and leaking one on
    // every failed attempt would eventually make psa_generate_key() fail.
    if (use_encryption) {
        if (bluettiState.my_ephemeral_key_valid) {
            psa_destroy_key(bluettiState.my_ephemeral_priv_key_id);
            bluettiState.my_ephemeral_key_valid = false;
        }
        if (!ecdh_generate_ephemeral_keypair(&bluettiState.my_ephemeral_priv_key_id, bluettiState.my_ephemeral_pub)) {
            ESP_LOGE(TAG, "connect_to_bluetti: failed to pre-generate ephemeral keypair");
            return false;
        }
        bluettiState.my_ephemeral_key_valid = true;
    }

    // --- Step 1: scan for the station, then connect + subscribe ---
    struct ble_gap_disc_params disc_params = {};
    disc_params.itvl = 0x0010;
    disc_params.window = 0x0010;
    disc_params.passive = 0;
    disc_params.filter_duplicates = 1;

    int rc = ble_gap_disc(bluettiState.own_addr_type, 10000 /* ms */, &disc_params, gap_event_cb, nullptr);
    if (rc != 0) {
        ESP_LOGE(TAG, "connect_to_bluetti: ble_gap_disc failed: %d", rc);
        return false;
    }

    // This single semaphore is given exactly once, either after a
    // successful CCCD subscribe (g.gap_step_ok = true) or after any failure
    // along the way (g.gap_step_ok = false) - see gap_event_cb/chr_disc_cb/
    // dsc_disc_cb/subscribe_write_cb above.
    if (xSemaphoreTake(bluettiState.sem_gap_step, pdMS_TO_TICKS(20000)) != pdTRUE) {
        ESP_LOGE(TAG, "connect_to_bluetti: timed out connecting/subscribing");
        return false;
    }
    if (!bluettiState.gap_step_ok) {
        ESP_LOGE(TAG, "connect_to_bluetti: connection setup failed - see errors above");
        return false;
    }

    if (!use_encryption) {
        ESP_LOGI(TAG, "Connected (no encryption) - ready to send commands");
        return true;
    }

    // --- Step 2: wait for the encryption handshake to complete. The
    // station starts sending handshake messages automatically as soon as we
    // subscribe, so we just wait for handle_key_accepted() to signal us. ---
    ESP_LOGI(TAG, "Waiting for encryption handshake...");
    if (xSemaphoreTake(bluettiState.sem_handshake, pdMS_TO_TICKS(20000)) != pdTRUE) {
        ESP_LOGE(TAG, "connect_to_bluetti: encryption handshake timed out");
        return false;
    }
    return bluettiState.handshake_ok;
}

bool get_all_data(bluetti_data_t *out_data)
{
    if (!out_data) return false;
    memset(out_data, 0, sizeof(*out_data));

    if (bluettiState.conn_handle == BLE_HS_CONN_HANDLE_NONE) {
        ESP_LOGE(TAG, "get_all_data: not connected - call connect_to_bluetti() first");
        return false;
    }
    if (bluettiState.use_encryption && bluettiState.stage != HS_READY) {
        ESP_LOGE(TAG, "get_all_data: encryption handshake not complete yet");
        return false;
    }

    xSemaphoreTake(bluettiState.mutex, portMAX_DELAY);

    bool all_ok = true;
    uint16_t raw;

    if (read_u16(REG_BATTERY_SOC, &raw)) {
        out_data->battery_soc = (float)raw;
    } else {
        all_ok = false;
    }

    if (read_u16(REG_DC_OUTPUT_POWER, &raw)) {
        out_data->dc_output_power = (float)raw;
    } else {
        all_ok = false;
    }

    if (read_u16(REG_AC_OUTPUT_POWER, &raw)) {
        out_data->ac_output_power = (float)raw;
    } else {
        all_ok = false;
    }

    if (read_u16(REG_DC_INPUT_POWER, &raw)) {
        out_data->dc_input_power = (float)raw;
    } else {
        all_ok = false;
    }

    if (read_u16(REG_AC_INPUT_POWER, &raw)) {
        out_data->ac_input_power = (float)raw;
    } else {
        all_ok = false;
    }

    if (read_u16(REG_AC_INPUT_VOLTAGE, &raw)) {
        out_data->ac_input_voltage = (float)raw / 10.0f; // DecimalField scale=1
    } else {
        all_ok = false;
    }

    if (!read_device_type(out_data->device_type, sizeof(out_data->device_type))) {
        all_ok = false;
    }

    xSemaphoreGive(bluettiState.mutex);

    out_data->valid = all_ok;
    return all_ok;
}

// Reads the current state of a switch-type register (0/1, e.g. REG_CTRL_AC/
// REG_CTRL_DC), flips it, and writes the new value back. Reads fresh state
// every time rather than trusting a remembered value, so this can't drift
// out of sync with reality if the station's actual state ever changed some
// other way (its own physical button, a previous write we thought failed
// but didn't, etc). On success, `*out_new_state` is the value it was
// switched TO.
static bool toggle_switch_register(uint16_t address, bool *out_new_state)
{
    if (bluettiState.conn_handle == BLE_HS_CONN_HANDLE_NONE) {
        ESP_LOGE(TAG, "toggle_switch_register(0x%04x): not connected", address);
        return false;
    }
    if (bluettiState.use_encryption && bluettiState.stage != HS_READY) {
        ESP_LOGE(TAG, "toggle_switch_register(0x%04x): encryption handshake not complete yet", address);
        return false;
    }

    xSemaphoreTake(bluettiState.mutex, portMAX_DELAY);

    uint16_t current = 0;
    bool ok = read_u16(address, &current);
    if (ok) {
        uint16_t next = current ? 0 : 1;
        ok = write_register(address, next);
        if (ok) {
            *out_new_state = (next != 0);
        }
    }

    xSemaphoreGive(bluettiState.mutex);
    return ok;
}

bool toggle_ac_output(bool *out_new_state)
{
    return toggle_switch_register(REG_CTRL_AC, out_new_state);
}

bool toggle_dc_output(bool *out_new_state)
{
    return toggle_switch_register(REG_CTRL_DC, out_new_state);
}

void stop_connection(void)
{
    if (bluettiState.conn_handle != BLE_HS_CONN_HANDLE_NONE) {
        // Drain any stale signal left over from an earlier disconnect
        // (e.g. one nobody waited on) so the take below can't return
        // instantly on a leftover give instead of THIS disconnect actually
        // completing - same idiom used for sem_response in read_register().
        xSemaphoreTake(bluettiState.sem_disconnect, 0);

        int rc = ble_gap_terminate(bluettiState.conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        bluettiState.conn_handle = BLE_HS_CONN_HANDLE_NONE;

        // ble_gap_terminate() only SENDS the disconnect request - it
        // returns before the link is actually torn down. Calling
        // connect_to_bluetti() again immediately after stop_connection()
        // used to race against that teardown (both at the NimBLE host
        // level and against the station, which may need a moment after
        // disconnecting before it resumes advertising), causing the
        // reconnect attempt to fail unpredictably. Waiting here for the
        // real BLE_GAP_EVENT_DISCONNECT (which gives this semaphore) means
        // callers can rely on the link being fully down by the time this
        // function returns.
        if (rc == 0) {
            if (xSemaphoreTake(bluettiState.sem_disconnect, pdMS_TO_TICKS(5000)) != pdTRUE) {
                ESP_LOGW(TAG, "stop_connection: timed out waiting for disconnect confirmation");
            }
        }
    }
    bluettiState.have_target_addr = false;
    bluettiState.stage = HS_NOT_STARTED;
    bluettiState.handshake_ok = false;
    bluettiState.cccd_handle = 0;
    bluettiState.write_val_handle = 0;
    bluettiState.notify_val_handle = 0;
    if (bluettiState.my_ephemeral_key_valid) {
        // The handshake was stopped before handle_key_accepted() ever got
        // to consume/destroy the speculatively-generated keypair from
        // connect_to_bluetti() - clean it up here instead, so it doesn't
        // leak a PSA key slot.
        psa_destroy_key(bluettiState.my_ephemeral_priv_key_id);
        bluettiState.my_ephemeral_key_valid = false;
    }
    memset(bluettiState.unsecure_aes_key, 0, sizeof(bluettiState.unsecure_aes_key));
    memset(bluettiState.unsecure_aes_iv, 0, sizeof(bluettiState.unsecure_aes_iv));
    memset(bluettiState.secure_aes_key, 0, sizeof(bluettiState.secure_aes_key));
    ESP_LOGI(TAG, "Disconnected from station");
}
