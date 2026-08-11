// =============================================================================
// data_logger.cpp
// =============================================================================
// See data_logger.h for the "how to use this" docs and the timestamp
// caveat. This file is the storage mechanism only - it doesn't decide WHEN
// to log, or what to do with history once read back (that's main.cpp/
// chart.cpp's job, same division of responsibility as telegram_bot.cpp).
//
// If you're coming from C#: esp_vfs_fat_spiflash_mount_rw_wl() is roughly
// like mounting a small virtual disk backed by a region of flash instead of
// a real storage device. Once mounted, ESP-IDF's VFS (virtual filesystem)
// layer means normal libc file functions - fopen/fwrite/fclose - just work
// on paths under the mount point (here, "/data/..."), the same as they
// would in a desktop C# app calling into the OS filesystem. You don't see
// any of that plumbing from the call site; it's handled once, in
// data_logger_init().
// =============================================================================

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

#include "esp_vfs_fat.h"
#include "esp_log.h"
#include "esp_timer.h"

#include "data_logger.h"

static const char *TAG = "data_logger";

// Must match the partition's Name column in partitions.csv exactly - this
// is how esp_vfs_fat_spiflash_mount_rw_wl() finds the right flash region.
static const char *PARTITION_LABEL = "storage";
// Where the mounted filesystem shows up in the VFS path namespace - an
// arbitrary choice (any leading "/name" is fine), just needs to match
// between here and the file path used below.
static const char *MOUNT_POINT = "/data";
static const char *LOG_FILE_PATH = "/data/bluetti.log";

// One logged sample. `#pragma pack(push, 1)` disables the compiler's
// usual padding-for-alignment (which would otherwise round this up to a
// tidier but wasteful size) - we want the exact byte layout on flash, with
// no gaps, since every byte here is multiplied across however many
// thousands of records end up on the partition.
//
// Field sizing: power values are stored as int16_t (Watts) rather than
// float - this Bluetti model's power readings are always whole watts well
// within +-32767, so nothing is lost, and it's a quarter the size of a
// float. Battery is 0-100 so a single byte is exactly enough. Voltage is
// stored as tenths-of-a-volt (matching how bluetti_ble.cpp already scales
// it) in a uint16_t.
#pragma pack(push, 1)
struct LogRecord {
    uint32_t timestamp;           // seconds since THIS boot - see data_logger.h
    uint8_t  battery_soc;         // 0-100 (%)
    int16_t  ac_input_power;      // Watts
    int16_t  ac_output_power;     // Watts
    int16_t  dc_input_power;      // Watts
    int16_t  dc_output_power;     // Watts
    uint16_t ac_input_voltage_dv; // Volts * 10
};
#pragma pack(pop)

static wl_handle_t s_wl_handle = WL_INVALID_HANDLE;
static FILE *s_log_file = nullptr;
static bool s_mounted = false;

bool data_logger_init(void)
{
    if (s_mounted) {
        return true;
    }

    // format_if_mount_failed=true: a brand new/blank partition has no
    // filesystem on it yet (it's just erased flash), which looks like a
    // "mount failed" error the first time - this tells ESP-IDF to format
    // it automatically in that case, rather than requiring a separate
    // manual format step before first use.
    esp_vfs_fat_mount_config_t mount_config = {};
    mount_config.format_if_mount_failed = true;
    mount_config.max_files = 2;
    mount_config.allocation_unit_size = 0; // 0 = let FATFS pick, based on CONFIG_WL_SECTOR_SIZE

    esp_err_t err = esp_vfs_fat_spiflash_mount_rw_wl(MOUNT_POINT, PARTITION_LABEL, &mount_config, &s_wl_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "data_logger_init: failed to mount \"%s\" partition: %s",
                 PARTITION_LABEL, esp_err_to_name(err));
        return false;
    }

    // "ab" = append, binary. Every write lands at the current end of the
    // file regardless of any prior seeking - exactly what a pure log
    // (never rewriting old records) needs, and it means this same fopen()
    // call is correct whether the file already has years of history in it
    // or doesn't exist yet at all (append mode creates it).
    s_log_file = fopen(LOG_FILE_PATH, "ab");
    if (!s_log_file) {
        ESP_LOGE(TAG, "data_logger_init: failed to open %s for appending", LOG_FILE_PATH);
        esp_vfs_fat_spiflash_unmount_rw_wl(MOUNT_POINT, s_wl_handle);
        s_wl_handle = WL_INVALID_HANDLE;
        return false;
    }

    uint64_t total_bytes = 0, free_bytes = 0;
    esp_vfs_fat_info(MOUNT_POINT, &total_bytes, &free_bytes);
    long existing_size = ftell(s_log_file); // append mode starts positioned at EOF, so this is the file's current size
    ESP_LOGI(TAG, "Mounted log partition: %llu/%llu bytes free, existing log is %ld bytes (~%ld records)",
             (unsigned long long)free_bytes, (unsigned long long)total_bytes,
             existing_size, existing_size / (long)sizeof(LogRecord));

    s_mounted = true;
    return true;
}

bool data_logger_append(const bluetti_data_t *data)
{
    if (!s_mounted) {
        ESP_LOGE(TAG, "data_logger_append: data_logger_init() was never called (or failed)");
        return false;
    }

    LogRecord record;
    // Real UTC epoch seconds, synced via NTP in main.cpp's time_sync_init()
    // (called once, right after WiFi connects). If sync hasn't succeeded
    // yet when this runs (e.g. logged right after boot, before the first
    // NTP round-trip completes), time(NULL) just returns whatever the
    // system clock defaults to - an obviously-wrong pre-1970-ish value -
    // rather than failing outright; easy to spot in the data if it happens.
    record.timestamp = (uint32_t)time(NULL);
    record.battery_soc = (uint8_t)data->battery_soc;
    record.ac_input_power = (int16_t)data->ac_input_power;
    record.ac_output_power = (int16_t)data->ac_output_power;
    record.dc_input_power = (int16_t)data->dc_input_power;
    record.dc_output_power = (int16_t)data->dc_output_power;
    record.ac_input_voltage_dv = (uint16_t)(data->ac_input_voltage * 10.0f);

    if (fwrite(&record, sizeof(record), 1, s_log_file) != 1) {
        ESP_LOGE(TAG, "data_logger_append: fwrite failed");
        return false;
    }

    // fflush() only pushes libc's own userspace buffer down to the VFS/
    // FATFS layer - it doesn't guarantee the bytes have actually reached
    // the flash chip yet. fsync() goes the rest of the way (maps down to
    // FATFS's f_sync()). Doing both, every record, costs a little time but
    // means a successful return here is a real guarantee: if the board
    // loses power the instant after this function returns true, this
    // record is not lost. Given records are only appended once every
    // logging interval (not every 10s live-poll cycle - see main.cpp),
    // that cost is negligible next to the durability it buys.
    fflush(s_log_file);
    fsync(fileno(s_log_file));

    return true;
}

size_t data_logger_read_recent(uint32_t seconds_back, data_logger_point_t *out_points, size_t max_points)
{
    if (!s_mounted || !out_points || max_points == 0) {
        return 0;
    }

    // Make sure anything we've appended (buffered in s_log_file, possibly
    // not yet visible to a separate read handle) is actually on flash
    // before opening a fresh read of the same file.
    fflush(s_log_file);

    FILE *f = fopen(LOG_FILE_PATH, "rb");
    if (!f) {
        ESP_LOGE(TAG, "data_logger_read_recent: failed to open %s for reading", LOG_FILE_PATH);
        return 0;
    }

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    long total_records = file_size / (long)sizeof(LogRecord);

    uint32_t now = (uint32_t)time(NULL);
    uint32_t cutoff = (now > seconds_back) ? (now - seconds_back) : 0;

    // Walk backward from the newest record. Because records are always
    // appended in chronological order, timestamps only ever increase as we
    // go forward through the file - so the moment we hit one older than
    // `cutoff`, everything before it is guaranteed older too, and we can
    // stop without scanning the rest of a potentially huge file.
    //
    // Matches are written into the TAIL end of out_points first (working
    // backward from out_points[max_points-1]), simply because we don't
    // know the final count up front. Once done, the memmove below slides
    // them down to start at index 0, oldest-first - the order a
    // left-to-right time-axis chart wants.
    size_t count = 0;
    LogRecord record;

    for (long i = total_records - 1; i >= 0 && count < max_points; i--) {
        if (fseek(f, i * (long)sizeof(LogRecord), SEEK_SET) != 0) break;
        if (fread(&record, sizeof(record), 1, f) != 1) break;
        if (record.timestamp < cutoff) break;

        data_logger_point_t *slot = &out_points[max_points - 1 - count];
        slot->timestamp = record.timestamp;
        slot->battery_soc = (float)record.battery_soc;
        slot->ac_input_power = (float)record.ac_input_power;
        slot->ac_output_power = (float)record.ac_output_power;
        slot->dc_input_power = (float)record.dc_input_power;
        slot->dc_output_power = (float)record.dc_output_power;
        slot->ac_input_voltage = (float)record.ac_input_voltage_dv / 10.0f;
        count++;
    }

    fclose(f);

    if (count > 0 && count < max_points) {
        memmove(out_points, &out_points[max_points - count], count * sizeof(data_logger_point_t));
    }

    return count;
}
