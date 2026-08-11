// =============================================================================
// chart.cpp
// =============================================================================
// See chart.h for the overall approach. This file: reads history via
// data_logger_read_recent(), downsamples it to a chart-friendly point
// count, hand-builds a Chart.js v2 config as JSON text (no cJSON in this
// build - same reasoning as telegram_bot.cpp's json_escape_into), URL-
// encodes it, and sends the resulting QuickChart URL via
// telegram_send_photo_url().
//
// Stack safety: this can be called from main.cpp's loop, which runs on
// app_main's task (only ~3.5KB of stack - the same task that caused a
// stack-overflow crash the first time TLS work ran on it directly, before
// telegram_bot.cpp's worker-task fix). Every buffer here that could be more
// than a few hundred bytes (the raw point array, the JSON config, the
// URL-encoded copy) is deliberately heap-allocated (malloc/free), never a
// stack local.
// =============================================================================

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <time.h>

#include "esp_log.h"

#include "chart.h"
#include "data_logger.h"
#include "telegram_bot.h"

static const char *TAG = "chart";

// Chart.js line charts with more than a few dozen points get unreadable on
// a small Telegram preview image - cap it, and pick evenly-spaced samples
// out of however many raw records fall in the window (simple decimation,
// not averaging - good enough for "what's the trend" at a glance).
#define MAX_CHART_POINTS 50

// snprintf's return value tells you how many bytes WOULD have been written,
// even past the end of the buffer - that's what lets append() safely
// no-op once `buf` is full instead of corrupting anything, rather than
// needing every call site to separately check remaining space.
static size_t append(char *buf, size_t cap, size_t pos, const char *fmt, ...)
{
    if (pos >= cap) {
        return pos;
    }
    va_list args;
    va_start(args, fmt);
    int written = vsnprintf(buf + pos, cap - pos, fmt, args);
    va_end(args);
    if (written < 0) {
        return pos;
    }
    size_t new_pos = pos + (size_t)written;
    return (new_pos < cap) ? new_pos : cap;
}

// Percent-encodes everything except RFC 3986 "unreserved" characters
// (letters, digits, - _ . ~) for use as a URL query parameter value.
// Truncates (leaves a valid, just-shorter, null-terminated string) rather
// than overflowing if `out_cap` is too small.
static void url_encode_into(const char *src, char *out, size_t out_cap)
{
    static const char *hex = "0123456789ABCDEF";
    size_t o = 0;
    for (size_t i = 0; src[i] != '\0' && o + 4 < out_cap; i++) {
        unsigned char c = (unsigned char)src[i];
        bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                           (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~';
        if (unreserved) {
            out[o++] = (char)c;
        } else {
            out[o++] = '%';
            out[o++] = hex[(c >> 4) & 0xF];
            out[o++] = hex[c & 0xF];
        }
    }
    out[o] = '\0';
}

bool chart_send_recent(float hours)
{
    if (hours <= 0.0f) {
        hours = 1.0f;
    }
    // No reason a fat-fingered "/chart 99999" should try to scan an
    // unbounded window - 30 days is already far more than the "storage"
    // partition holds at the current logging interval.
    if (hours > 24.0f * 30.0f) {
        hours = 24.0f * 30.0f;
    }

    uint32_t seconds_back = (uint32_t)(hours * 3600.0f);

    // Raw read cap: comfortably covers the requested window at the ~1-
    // minute logging interval (see main.cpp), with slack, but bounded so a
    // silly-large `hours` doesn't ask for an unbounded allocation.
    size_t raw_cap = (size_t)(hours * 60.0f) + 20;
    if (raw_cap > 3000) {
        raw_cap = 3000;
    }

    data_logger_point_t *raw_points = (data_logger_point_t *)malloc(raw_cap * sizeof(data_logger_point_t));
    if (!raw_points) {
        ESP_LOGE(TAG, "chart_send_recent: out of memory (raw_points, %zu points)", raw_cap);
        return false;
    }

    size_t count = data_logger_read_recent(seconds_back, raw_points, raw_cap);
    if (count == 0) {
        ESP_LOGW(TAG, "chart_send_recent: no logged history in the last %.1fh", hours);
        free(raw_points);
        return false;
    }

    size_t out_count = (count < MAX_CHART_POINTS) ? count : MAX_CHART_POINTS;
    // Every point still gets plotted - this only controls how many get a
    // visible "HH:MM" label under them, so the x-axis doesn't turn into an
    // unreadable smear of ~50 overlapping labels. About 8 labels shown
    // regardless of how many points there are.
    size_t label_stride = (out_count > 8) ? (out_count + 7) / 8 : 1;

    // Chart.js v2 config, built as plain text. 8KB comfortably fits 50
    // points x 5 datasets plus labels and boilerplate.
    size_t config_cap = 8192;
    char *config = (char *)malloc(config_cap);
    if (!config) {
        ESP_LOGE(TAG, "chart_send_recent: out of memory (config)");
        free(raw_points);
        return false;
    }

    size_t pos = 0;
    pos = append(config, config_cap, pos, "{\"type\":\"line\",\"data\":{\"labels\":[");

    for (size_t i = 0; i < out_count; i++) {
        size_t idx = (out_count <= 1) ? 0 : (size_t)((uint64_t)i * (count - 1) / (out_count - 1));
        bool show_label = (i % label_stride == 0) || (i == out_count - 1);
        const char *sep = (i == 0) ? "" : ",";
        if (show_label) {
            time_t ts = (time_t)raw_points[idx].timestamp;
            struct tm tm_buf;
            gmtime_r(&ts, &tm_buf);
            char label[8];
            strftime(label, sizeof(label), "%H:%M", &tm_buf);
            pos = append(config, config_cap, pos, "%s\"%s\"", sep, label);
        } else {
            pos = append(config, config_cap, pos, "%s\"\"", sep);
        }
    }
    pos = append(config, config_cap, pos, "],\"datasets\":[");

    // Power draws share a left axis (comparable magnitude, tens-to-low-
    // thousands of Watts); battery % gets its own right axis fixed to
    // 0-100 - putting it on the power axis would flatten it to a barely-
    // visible line near the bottom. AC input voltage (~230V, logged but
    // not plotted here) doesn't share a sensible scale with either, so
    // it's deliberately left out of this default chart.
    struct {
        const char *label;
        const char *color;
        bool is_battery;
    } series[] = {
        {"AC In (W)",   "#2ecc71", false},
        {"AC Out (W)",  "#e74c3c", false},
        {"DC In (W)",   "#3498db", false},
        {"DC Out (W)",  "#9b59b6", false},
        {"Battery (%)", "#f39c12", true},
    };

    for (size_t s = 0; s < 5; s++) {
        pos = append(config, config_cap, pos,
                     "%s{\"label\":\"%s\",\"borderColor\":\"%s\",\"fill\":false,\"pointRadius\":0,\"yAxisID\":\"%s\",\"data\":[",
                     (s == 0) ? "" : ",", series[s].label, series[s].color,
                     series[s].is_battery ? "battery" : "power");
        for (size_t i = 0; i < out_count; i++) {
            size_t idx = (out_count <= 1) ? 0 : (size_t)((uint64_t)i * (count - 1) / (out_count - 1));
            const data_logger_point_t *p = &raw_points[idx];
            float value = series[s].is_battery ? p->battery_soc
                        : (s == 0) ? p->ac_input_power
                        : (s == 1) ? p->ac_output_power
                        : (s == 2) ? p->dc_input_power
                        : p->dc_output_power;
            pos = append(config, config_cap, pos, "%s%.0f", (i == 0) ? "" : ",", value);
        }
        pos = append(config, config_cap, pos, "]}");
    }

    // Matches the user-shown QuickChart sandbox example: Chart.js v2
    // syntax, xAxes/yAxes as arrays, scaleLabel for visible axis titles,
    // gridLines left on (default) so the scale lines show. The battery
    // axis turns its own gridlines off (drawOnChartArea:false) so they
    // don't overlap/clash with the power axis's gridlines.
    pos = append(config, config_cap, pos,
                 "]},\"options\":{\"title\":{\"display\":true,\"text\":\"Bluetti - last %.1fh (UTC)\"},"
                 "\"scales\":{"
                 "\"xAxes\":[{\"scaleLabel\":{\"display\":true,\"labelString\":\"Time (UTC)\"}}],"
                 "\"yAxes\":["
                 "{\"id\":\"power\",\"position\":\"left\",\"scaleLabel\":{\"display\":true,\"labelString\":\"Power (W)\"}},"
                 "{\"id\":\"battery\",\"position\":\"right\",\"scaleLabel\":{\"display\":true,\"labelString\":\"Battery (%%)\"},"
                 "\"ticks\":{\"min\":0,\"max\":100},\"gridLines\":{\"drawOnChartArea\":false}}"
                 "]}}}",
                 hours);

    if (pos >= config_cap - 1) {
        ESP_LOGW(TAG, "chart_send_recent: config buffer filled up (%zu bytes) - chart may be truncated/malformed", config_cap);
    }

    free(raw_points);

    // Worst case every byte of the config becomes a 3-byte %XX escape.
    size_t encoded_cap = pos * 3 + 1;
    char *encoded = (char *)malloc(encoded_cap);
    if (!encoded) {
        ESP_LOGE(TAG, "chart_send_recent: out of memory (encoded)");
        free(config);
        return false;
    }
    url_encode_into(config, encoded, encoded_cap);
    free(config);

    size_t url_cap = encoded_cap + 64;
    char *chart_url = (char *)malloc(url_cap);
    if (!chart_url) {
        ESP_LOGE(TAG, "chart_send_recent: out of memory (chart_url)");
        free(encoded);
        return false;
    }
    snprintf(chart_url, url_cap, "https://quickchart.io/chart?w=600&h=400&c=%s", encoded);
    free(encoded);

    ESP_LOGI(TAG, "chart_send_recent: sending chart (%zu of %zu logged points, %zu char URL)",
             out_count, count, strlen(chart_url));

    char caption[64];
    snprintf(caption, sizeof(caption), "Last %.1fh", hours);
    bool ok = telegram_send_photo_url(chart_url, caption);
    if (!ok) {
        ESP_LOGE(TAG, "chart_send_recent: telegram_send_photo_url failed");
    }

    free(chart_url);
    return ok;
}
