// =============================================================================
// chart.h
// =============================================================================
// Builds a QuickChart.io line chart from logged Bluetti history (see
// data_logger.h) and sends it to Telegram as a photo (see telegram_bot.h).
// Doesn't touch flash or the network config itself - it's glue between
// those two modules plus some string building.
//
// How the image actually gets to Telegram: this module builds a Chart.js
// v2 config as JSON, URL-encodes it into a
// "https://quickchart.io/chart?c=<config>" URL, and hands that URL string
// to telegram_send_photo_url(). Telegram's own servers fetch the image
// from QuickChart - this ESP32 never downloads or handles any image bytes,
// just builds and sends a URL string.
//
// Usage from main.cpp (after telegram_bot_init() and data_logger_init()):
//
//     #include "chart.h"
//
//     chart_send_recent(1.0f);  // last 1 hour
//     chart_send_recent(6.0f);  // last 6 hours
// =============================================================================

#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Builds a chart covering the last `hours` hours of logged history (AC/DC
// input/output power on the left axis, battery % on the right) and sends
// it to the configured Telegram chat. `hours` is clamped to a sane range
// (0, 720] - values <= 0 fall back to 1 hour.
//
// Returns false if there's no logged history in the requested window, or
// if building/sending the chart failed for any reason (out of memory,
// HTTP failure, Telegram rejected it) - check the serial log either way.
bool chart_send_recent(float hours);

#ifdef __cplusplus
}
#endif
