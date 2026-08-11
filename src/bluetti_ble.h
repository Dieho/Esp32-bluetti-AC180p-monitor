// =============================================================================
// bluetti_ble.h
// =============================================================================
// Public API for talking to a Bluetti AC180P power station over Bluetooth LE.
//
// If you're coming from C#: this header is the "interface" - the only thing
// main.cpp needs to #include. bluetti_ble.cpp is the "implementation",
// hidden away (nothing here exposes internal state or helper functions).
//
// Usage from main.cpp:
//
//     #include "bluetti_ble.h"
//
//     bluetti_data_t data;
//     if (connect_to_bluetti("0A:BE:6D:21:B1:04", true)) {
//         if (get_all_data(&data)) {
//             ESP_LOGI("APP", "Battery: %.0f%%", data.battery_soc);
//         }
//         stop_connection();
//     }
//
// Protocol details (framing, crypto, register map) are transcribed from the
// open-source Python project github.com/Patrick762/bluetti-bt-lib.
// =============================================================================

#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// One "snapshot" of readings from the station. Power in Watts, voltage in
// Volts, battery in percent (0-100).
//
// `valid` is only true if every field below was read successfully this
// cycle - if the BLE link hiccups mid-read, `valid` is false and you should
// just try again on the next get_all_data() call.
typedef struct {
    bool  valid;
    float battery_soc;       // Battery state of charge, 0-100 (%)
    float ac_input_power;    // Power coming IN from the wall/generator (W)
    float ac_output_power;   // Power going OUT to AC devices (W)
    float dc_input_power;    // Power coming IN from solar/DC (W)
    float dc_output_power;   // Power going OUT to USB/DC devices (W)
    float ac_input_voltage;  // AC input line voltage (V)
} bluetti_data_t;

// Connects to the station and performs the handshake needed before it will
// answer requests.
//
//   mac_address    - the station's BLE MAC address, colon-separated, e.g.
//                    "0A:BE:6D:21:B1:04".
//   use_encryption - true if the station requires the encrypted protocol
//                    (most newer Bluetti stations do).
//
// BLOCKS the calling FreeRTOS task until the connection (+ handshake, if
// applicable) succeeds or fails/times out - can take several seconds.
// Returns true on success. Call again to retry on failure.
//
// Needs a task with a reasonably large stack (BLE + crypto use a fair
// amount) - 8192 bytes is a safe minimum if you spawn your own task for
// this rather than calling it from app_main.
//
// Requires nvs_flash_init() to have already been called once at startup
// (NimBLE needs NVS, same as WiFi does).
bool connect_to_bluetti(const char *mac_address, bool use_encryption);

// Reads all supported fields in one go (battery, AC/DC input/output power,
// AC input voltage). Blocks until done - each field is a separate
// request/response round-trip over BLE, so this takes a few seconds.
//
// Safe to call repeatedly after a single connect_to_bluetti() - no need to
// reconnect between reads. For polling, just call this every N seconds from
// a FreeRTOS task.
//
// Returns true only if ALL fields were read successfully (also reflected in
// out_data->valid).
bool get_all_data(bluetti_data_t *out_data);

// Disconnects and resets internal state so connect_to_bluetti() can be
// called again (same or different station). Safe to call even if not
// currently connected.
void stop_connection(void);

#ifdef __cplusplus
}
#endif
