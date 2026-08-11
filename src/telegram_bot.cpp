// =============================================================================
// telegram_bot.cpp
// =============================================================================
// Sends messages via the Telegram Bot API's sendMessage endpoint over HTTPS,
// using ESP-IDF's esp_http_client. No JSON library is used - this ESP-IDF
// build doesn't bundle cJSON, and the one request/response shape we need
// here is small enough to hand-build safely (same "avoid an extra
// dependency for a narrow need" call bluetti_ble.cpp makes with its own
// self-contained MD5).
//
// If you're coming from C#: telegram_send_message() is a lot like calling
// `httpClient.PostAsync(url, content).Result` from the caller's point of
// view - it blocks the calling task until the whole request/response
// round-trip is done, rather than being awaitable. There's no async/await
// in C; "blocking call from a task" is the normal pattern here, same as
// connect_to_bluetti()/get_all_data() in bluetti_ble.cpp.
//
// Under the hood, though, the actual HTTPS/TLS work does NOT run on
// whichever task calls telegram_send_message() - see the big comment on
// telegram_worker_task() below for why, and bluetti_ble.cpp's
// notify_worker_task() for the same pattern solving the same class of
// problem (a small-stack caller task vs. a stack-hungry crypto operation).
// =============================================================================

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_http_client.h"
#include "esp_crt_bundle.h"

#include "telegram_bot.h"

static const char *TAG = "telegram_bot";

// Which HTTP operation telegram_worker_task() should perform next - see the
// "job" fields on TelegramState below.
enum class TelegramJob {
    SEND_MESSAGE,
    POLL_MESSAGE,
};

// All mutable state for this module - see BluettiState in bluetti_ble.cpp
// for the same "one global struct instead of a class instance" pattern.
struct TelegramState {
    char bot_token[96] = {0};
    char chat_id[40] = {0};
    bool initialized = false;

    // Serializes calls to telegram_send_message()/telegram_poll_message() -
    // without it, two tasks calling in at the same time would stomp on the
    // shared job_*/response_buf fields below. Same role as a C#
    // `lock`/SemaphoreSlim around shared state.
    SemaphoreHandle_t mutex = nullptr;

    // --- Handoff to/from telegram_worker_task() - see that function's
    // comment for why this indirection exists. Only ONE of these is ever
    // "in flight" at a time, guaranteed by `mutex` above, so a single
    // shared job description (rather than a queue of them) is enough.
    TaskHandle_t worker_task_handle = nullptr;
    SemaphoreHandle_t worker_start = nullptr; // caller -> worker: "job is ready, go"
    SemaphoreHandle_t worker_done = nullptr;  // worker -> caller: "job_result is ready"
    TelegramJob job_type;
    const char *job_text;      // SEND_MESSAGE input: text to send
    char *job_out_text;        // POLL_MESSAGE output: where to write the result
    size_t job_out_cap;
    bool job_result;

    // Filled in by http_event_handler() while a request is in flight, so
    // the worker can inspect Telegram's response body afterward
    // (esp_http_client doesn't buffer the response for you - you either
    // stream it via a callback, which is what this does, or read it
    // manually after esp_http_client_perform(); the callback is simpler
    // here since responses are always small).
    char response_buf[512];
    size_t response_len = 0;

    // Telegram's getUpdates "offset" parameter: telling the server
    // "give me updates after this id" both skips old ones we've already
    // seen and tells Telegram it's safe to stop returning them. See
    // telegram_poll_message_impl() for how this gets advanced.
    long long update_offset = 0;
};
static TelegramState g;

static void telegram_worker_task(void *param);

void telegram_bot_init(const char *bot_token, const char *chat_id)
{
    if (!g.mutex) {
        g.mutex = xSemaphoreCreateMutex();
    }
    strncpy(g.bot_token, bot_token, sizeof(g.bot_token) - 1);
    g.bot_token[sizeof(g.bot_token) - 1] = '\0';
    strncpy(g.chat_id, chat_id, sizeof(g.chat_id) - 1);
    g.chat_id[sizeof(g.chat_id) - 1] = '\0';
    g.initialized = true;

    if (!g.worker_task_handle) {
        g.worker_start = xSemaphoreCreateBinary();
        g.worker_done = xSemaphoreCreateBinary();
        // 8KB: comfortably more than an HTTPS/TLS handshake + X.509 chain
        // verification against the CA bundle needs. Unlike the caller's
        // task (which might be app_main's own task, or a UI/button-polling
        // loop with a small stack - see the crash this replaced), this
        // task exists solely for this, so there's no reason to be tight
        // about its size.
        xTaskCreate(telegram_worker_task, "telegram_worker", 8192, nullptr, 5, &g.worker_task_handle);
    }
}

// Escapes `src` for safe embedding inside a JSON string literal (handles ",
// \, and the common control characters), writing into the caller-owned
// buffer `out` (always null-terminated). Truncates rather than overflows if
// `src` doesn't fit - same "caller owns the buffer, and it's sized to be
// generous" pattern as format_mac_address() in bluetti_ble.cpp.
static void json_escape_into(const char *src, char *out, size_t out_cap)
{
    size_t o = 0;
    for (size_t i = 0; src[i] != '\0' && o + 2 < out_cap; i++) {
        unsigned char c = (unsigned char)src[i];
        switch (c) {
            case '"':  out[o++] = '\\'; out[o++] = '"';  break;
            case '\\': out[o++] = '\\'; out[o++] = '\\'; break;
            case '\n': out[o++] = '\\'; out[o++] = 'n';  break;
            case '\r': out[o++] = '\\'; out[o++] = 'r';  break;
            case '\t': out[o++] = '\\'; out[o++] = 't';  break;
            default:
                if (c >= 0x20) {
                    out[o++] = (char)c;
                }
                // Other control characters (< 0x20): dropped rather than
                // emitted, since they'd otherwise produce invalid JSON.
                break;
        }
    }
    out[o] = '\0';
}

// esp_http_client calls this for each stage of the request (connected,
// headers sent, data received, ...). We only care about HTTP_EVENT_ON_DATA -
// each call may hand us just part of the response body, so we append to
// g.response_buf across however many calls it takes.
static esp_err_t http_event_handler(esp_http_client_event_t *evt)
{
    if (evt->event_id == HTTP_EVENT_ON_DATA) {
        size_t copy_len = (size_t)evt->data_len;
        size_t space = sizeof(g.response_buf) - 1 - g.response_len;
        if (copy_len > space) copy_len = space;
        if (copy_len > 0) {
            memcpy(g.response_buf + g.response_len, evt->data, copy_len);
            g.response_len += copy_len;
            g.response_buf[g.response_len] = '\0';
        }
    }
    return ESP_OK;
}

// --- Narrow, hand-rolled JSON field extraction ------------------------------
// These two only handle the specific shape of Telegram's getUpdates
// response (see telegram_poll_message() below) - they are NOT a general
// JSON parser. Each works by searching for `anchor` as a literal substring,
// which is safe here because the anchors used below are distinctive enough
// not to appear elsewhere within one update object. If you need something
// more robust, pull in a real JSON library instead of growing these by hand
// (ESP-IDF's cJSON/"json" component isn't included in this build).

// Finds `anchor` in `json` and copies the JSON number literal that follows
// (digits, optional leading '-') into `out` (null-terminated). Returns
// false if `anchor` isn't found or no digits follow it.
static bool find_json_number(const char *json, const char *anchor, char *out, size_t out_cap)
{
    const char *p = strstr(json, anchor);
    if (!p) return false;
    p += strlen(anchor);
    size_t o = 0;
    if (*p == '-' && o + 1 < out_cap) out[o++] = *p++;
    while (*p >= '0' && *p <= '9' && o + 1 < out_cap) {
        out[o++] = *p++;
    }
    out[o] = '\0';
    return o > 0;
}

// Finds `anchor` (which should include the opening quote, e.g.
// "\"text\":\"") and copies the JSON string value that follows into `out`,
// undoing the handful of escapes telegram_send_message() might have
// applied (\" \\ \n \r \t). Does NOT handle \uXXXX unicode escapes - fine
// for ASCII commands like "/status", not fine for arbitrary text with
// emoji/non-Latin characters.
static bool find_json_string(const char *json, const char *anchor, char *out, size_t out_cap)
{
    const char *p = strstr(json, anchor);
    if (!p) return false;
    p += strlen(anchor);
    size_t o = 0;
    while (*p != '\0' && *p != '"' && o + 1 < out_cap) {
        if (*p == '\\' && *(p + 1) != '\0') {
            p++;
            switch (*p) {
                case 'n': out[o++] = '\n'; break;
                case 'r': out[o++] = '\r'; break;
                case 't': out[o++] = '\t'; break;
                default:  out[o++] = *p;   break; // \" \\ \/ etc - literal char
            }
            p++;
        } else {
            out[o++] = *p++;
        }
    }
    out[o] = '\0';
    return true;
}

// Actual implementation of telegram_send_message() - runs on
// telegram_worker_task(), NOT on whatever task calls the public
// telegram_send_message() below. No locking in here: the caller already
// holds g.mutex for the whole job, so this has exclusive access to
// g.response_buf etc.
static bool telegram_send_message_impl(const char *text)
{
    char url[160];
    snprintf(url, sizeof(url), "https://api.telegram.org/bot%s/sendMessage", g.bot_token);

    // Body: {"chat_id":"<chat_id>","text":"<escaped text>"}
    char escaped_text[1024];
    json_escape_into(text, escaped_text, sizeof(escaped_text));

    char body[1200];
    int written = snprintf(body, sizeof(body), "{\"chat_id\":\"%s\",\"text\":\"%s\"}",
                           g.chat_id, escaped_text);
    if (written < 0 || (size_t)written >= sizeof(body)) {
        ESP_LOGE(TAG, "telegram_send_message: message too long, not sent");
        return false;
    }

    g.response_len = 0;
    g.response_buf[0] = '\0';

    esp_http_client_config_t config = {};
    config.url = url;
    config.method = HTTP_METHOD_POST;
    config.event_handler = http_event_handler;
    // Validates the server's TLS certificate against ESP-IDF's bundled set
    // of public CA certs, instead of us having to embed Telegram's
    // certificate manually (which would break whenever they rotate it).
    config.crt_bundle_attach = esp_crt_bundle_attach;
    config.timeout_ms = 10000;

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        ESP_LOGE(TAG, "telegram_send_message: esp_http_client_init failed");
        return false;
    }

    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, body, written);

    esp_err_t err = esp_http_client_perform(client);
    bool ok = false;
    if (err == ESP_OK) {
        int status = esp_http_client_get_status_code(client);
        // Telegram returns HTTP 200 even for some API-level failures (bad
        // chat_id, bot blocked by the user, etc), so the real signal is
        // "ok":true in the JSON body, not just the HTTP status code.
        ok = (status == 200) && (strstr(g.response_buf, "\"ok\":true") != nullptr);
        if (!ok) {
            ESP_LOGE(TAG, "telegram_send_message: failed (HTTP %d): %s", status, g.response_buf);
        }
    } else {
        ESP_LOGE(TAG, "telegram_send_message: HTTP request failed: %s", esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
    return ok;
}

bool telegram_send_messagef(const char *fmt, ...)
{
    char text[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(text, sizeof(text), fmt, args);
    va_end(args);
    return telegram_send_message(text);
}

// Actual implementation of telegram_poll_message() - runs on
// telegram_worker_task(). Same "no locking in here, caller already holds
// g.mutex for the whole job" reasoning as telegram_send_message_impl().
static bool telegram_poll_message_impl(char *out_text, size_t out_cap)
{
    // offset=<n> skips updates we've already consumed; timeout=0 and
    // limit=1 make this a short poll - it returns immediately with at most
    // one pending update, rather than blocking server-side waiting for one
    // to arrive (Telegram supports long-polling via a bigger `timeout`, but
    // that would stall the calling task for however long it waits).
    char url[192];
    snprintf(url, sizeof(url), "https://api.telegram.org/bot%s/getUpdates?offset=%lld&timeout=0&limit=1",
             g.bot_token, g.update_offset);

    g.response_len = 0;
    g.response_buf[0] = '\0';

    esp_http_client_config_t config = {};
    config.url = url;
    config.method = HTTP_METHOD_GET;
    config.event_handler = http_event_handler;
    config.crt_bundle_attach = esp_crt_bundle_attach;
    config.timeout_ms = 10000;

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        ESP_LOGE(TAG, "telegram_poll_message: esp_http_client_init failed");
        return false;
    }

    esp_err_t err = esp_http_client_perform(client);
    bool got_message = false;

    if (err == ESP_OK && esp_http_client_get_status_code(client) == 200) {
        char update_id_str[24];
        if (find_json_number(g.response_buf, "\"update_id\":", update_id_str, sizeof(update_id_str))) {
            // Advance the offset for EVERY update we see, even ones we end
            // up ignoring below (wrong chat, no text) - otherwise we'd keep
            // re-fetching the same ignored update forever.
            g.update_offset = strtoll(update_id_str, nullptr, 10) + 1;

            char chat_id_str[24];
            bool is_our_chat = find_json_number(g.response_buf, "\"chat\":{\"id\":", chat_id_str, sizeof(chat_id_str))
                                && strcmp(chat_id_str, g.chat_id) == 0;

            if (is_our_chat) {
                got_message = find_json_string(g.response_buf, "\"text\":\"", out_text, out_cap);
            } else {
                ESP_LOGW(TAG, "telegram_poll_message: ignoring message from unexpected chat_id=%s", chat_id_str);
            }
        }
        // No "update_id" found = "result":[] = nothing new waiting, which
        // isn't an error - got_message just stays false.
    } else {
        ESP_LOGE(TAG, "telegram_poll_message: HTTP request failed (err=%s)", esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
    return got_message;
}

// -----------------------------------------------------------------------
// Runs on its own FreeRTOS task (with a big stack, see telegram_bot_init())
// so that the HTTPS/TLS work inside telegram_send_message_impl()/
// telegram_poll_message_impl() never runs on whatever task calls the
// public telegram_send_message()/telegram_poll_message() below. Same
// producer/consumer pattern as bluetti_ble.cpp's notify_worker_task() -
// see that function's comment for the fuller explanation of why an RTOS
// task's stack is a small, fixed, hand-picked budget (unlike a .NET thread
// pool thread's 1MB default) and why overflowing it silently corrupts
// memory instead of throwing.
//
// This one's a bit different from notify_worker_task() in shape: that one
// is fire-and-forget (NimBLE hands it data and moves on), but
// telegram_send_message() needs to return a bool to its caller - so this
// is a small synchronous handoff instead: the caller fills in g.job_*,
// signals worker_start, and blocks on worker_done until this task has
// filled in g.job_result and signalled back. From the caller's point of
// view it's still just a blocking function call; the task hop is invisible
// to it.
// -----------------------------------------------------------------------
static void telegram_worker_task(void *param)
{
    for (;;) {
        xSemaphoreTake(g.worker_start, portMAX_DELAY);
        if (g.job_type == TelegramJob::SEND_MESSAGE) {
            g.job_result = telegram_send_message_impl(g.job_text);
        } else {
            g.job_result = telegram_poll_message_impl(g.job_out_text, g.job_out_cap);
        }
        xSemaphoreGive(g.worker_done);
    }
}

bool telegram_send_message(const char *text)
{
    if (!g.initialized) {
        ESP_LOGE(TAG, "telegram_send_message: telegram_bot_init() was never called");
        return false;
    }

    xSemaphoreTake(g.mutex, portMAX_DELAY);
    g.job_type = TelegramJob::SEND_MESSAGE;
    g.job_text = text;
    xSemaphoreGive(g.worker_start);
    xSemaphoreTake(g.worker_done, portMAX_DELAY);
    bool result = g.job_result;
    xSemaphoreGive(g.mutex);
    return result;
}

bool telegram_poll_message(char *out_text, size_t out_cap)
{
    if (!g.initialized) {
        ESP_LOGE(TAG, "telegram_poll_message: telegram_bot_init() was never called");
        return false;
    }

    xSemaphoreTake(g.mutex, portMAX_DELAY);
    g.job_type = TelegramJob::POLL_MESSAGE;
    g.job_out_text = out_text;
    g.job_out_cap = out_cap;
    xSemaphoreGive(g.worker_start);
    xSemaphoreTake(g.worker_done, portMAX_DELAY);
    bool result = g.job_result;
    xSemaphoreGive(g.mutex);
    return result;
}
