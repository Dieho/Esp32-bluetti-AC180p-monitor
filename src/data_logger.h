// =============================================================================
// data_logger.h
// =============================================================================
// Appends Bluetti readings (the 6 main characteristics: battery %, AC/DC
// input/output power, AC input voltage) to a small binary log file on a
// dedicated flash partition, so there's a history to look back on/graph
// later rather than only ever seeing the current reading.
//
// Storage: a wear-leveled FAT filesystem (ESP-IDF's esp_vfs_fat_spiflash_
// mount_rw_wl(), backed by the "storage" partition in partitions.csv - 8MB,
// carved out of flash this project wasn't using for anything else). Wear
// leveling spreads writes/erases across the whole partition automatically,
// so you don't have to think about flash wear here - see the comment on
// data_logger_append() for the actual numbers.
//
// Usage from main.cpp:
//
//     #include "data_logger.h"
//
//     data_logger_init();          // once, at startup
//     ...
//     data_logger_append(&data);   // each time you have a fresh reading you want kept
//
// NOTE on timestamps: records are tagged with real UTC epoch seconds
// (`time(NULL)`), kept accurate by an NTP sync that main.cpp runs once at
// startup (time_sync_init(), right after WiFi connects) - so unlike a
// boot-relative counter, timestamps from different reboots/sessions ARE
// directly comparable. The one edge case worth knowing: if data gets
// logged before that first NTP sync completes (e.g. very soon after boot,
// or if the network/NTP server was briefly unreachable), the timestamp
// will be an obviously-wrong low value (near the 1970 epoch) rather than
// the actual date - easy to spot if you ever see it in the data.
// =============================================================================

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "bluetti_ble.h"

#ifdef __cplusplus
extern "C" {
#endif

// One decoded history point, as returned by data_logger_read_recent()
// below. NOT the same as the compact on-disk record layout (that's
// private to data_logger.cpp) - this is the plain, easy-to-use shape
// callers (e.g. chart.cpp) actually want to work with.
typedef struct {
    uint32_t timestamp;      // real UTC epoch seconds - see the NOTE above
    float battery_soc;
    float ac_input_power;
    float ac_output_power;
    float dc_input_power;
    float dc_output_power;
    float ac_input_voltage;
} data_logger_point_t;

// Mounts the log partition (formatting it on first-ever use - a blank
// partition doesn't already contain a filesystem) and opens the log file
// for appending. Call once at startup, any time after nvs_flash_init().
// Safe to call more than once - later calls are no-ops if already mounted.
bool data_logger_init(void);

// Appends one record to the log file: the 6 main readings from `data`,
// tagged with a timestamp (see the NOTE above). Each record is a small
// fixed-size binary blob (about 15 bytes), not a growing text line, so
// this stays cheap no matter how large the log file gets.
//
// Flushes to flash before returning (not just to a RAM buffer), so a
// record that reports success survives a crash/reset/brownout immediately
// afterward - deliberately trading a little speed for not silently losing
// the record you just thought you'd saved.
bool data_logger_append(const bluetti_data_t *data);

// Reads back up to `max_points` of the most recent history within the last
// `seconds_back` seconds, oldest-first (left-to-right on a time axis) into
// `out_points`. Returns the number of points actually written (0 if the
// log is empty, nothing falls within the window, or on error).
//
// Efficient regardless of how large the log file has grown: since records
// are always appended in chronological order, this scans backward from the
// end of the file and stops as soon as it passes the time window, rather
// than reading the whole file every time.
size_t data_logger_read_recent(uint32_t seconds_back, data_logger_point_t *out_points, size_t max_points);

#ifdef __cplusplus
}
#endif
