// =============================================================================
// telegram_bot.h
// =============================================================================
// Minimal Telegram Bot API client for sending messages from the ESP32 (e.g.
// Bluetti status updates, low-battery alerts) and for polling for incoming
// commands (e.g. "/status"). This module does not interpret any message
// text itself and does not decide when to send anything - it just gives you
// send/receive primitives. Deciding WHEN to send, and what an incoming
// command like "/status" should DO, is entirely up to your own code.
//
// One-time setup, in Telegram:
//   1. Message @BotFather -> /newbot -> follow the prompts. You get a bot
//      token that looks like "123456789:AAExampleTokenTextGoesHere".
//   2. Send your new bot a message (or add it to a group), then open
//      https://api.telegram.org/bot<TOKEN>/getUpdates in a browser and find
//      your numeric chat id in the JSON response (the "chat":{"id": ...}
//      field).
//
// Usage from main.cpp (after WiFi is connected):
//
//     #include "telegram_bot.h"
//
//     telegram_bot_init("123456789:AAExampleTokenTextGoesHere", "987654321");
//     telegram_send_message("Bluetti monitor online");
//     ...
//     if (data.battery_soc < 20.0f) {
//         telegram_send_messagef("Battery low: %.0f%%", data.battery_soc);
//     }
//     ...
//     char msg[128];
//     if (telegram_poll_message(msg, sizeof(msg)) && strcmp(msg, "/status") == 0) {
//         telegram_send_messagef("Battery=%.0f%%", data.battery_soc);
//     }
//
// Requires WiFi to already be connected by the time you call any of the
// functions below - this module doesn't manage WiFi itself, it just
// performs an HTTPS request when asked.
// =============================================================================

#pragma once

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Stores the bot token and chat id for later use. Doesn't touch the network,
// so it's safe to call before WiFi is up. Call once at startup, before the
// first telegram_send_message()/telegram_send_messagef() call.
void telegram_bot_init(const char *bot_token, const char *chat_id);

// Sends a plain text message to the configured chat. Blocks until the HTTPS
// request completes (typically under a couple of seconds). Returns true only
// if Telegram's API confirmed the message was accepted ("ok":true in the
// response) - false on any network error, HTTP error, or API-level failure.
// Check the serial log either way for details.
bool telegram_send_message(const char *text);

// printf-style convenience wrapper around telegram_send_message() - formats
// into an internal buffer (up to ~500 characters) and sends the result. Same
// return value semantics as telegram_send_message().
bool telegram_send_messagef(const char *fmt, ...);

// Checks for a new incoming message sent to the bot since the last call,
// from the SAME chat configured in telegram_bot_init() - messages from any
// other chat are silently dropped (so a stranger who finds your bot can't
// trigger your logic). Uses Telegram's getUpdates endpoint with a short,
// non-blocking poll (returns immediately whether or not anything is
// waiting), so it's safe to call periodically from a loop - e.g. alongside
// however often you already call get_all_data() - rather than needing a
// dedicated task. Don't call it in a tight loop with no delay: that's an
// HTTPS request every call, and Telegram doesn't need to be asked that
// often for a personal bot.
//
// Returns true and fills `out_text` (up to out_cap - 1 bytes, always
// null-terminated) if a new text message arrived. Returns false if: nothing
// new is waiting, the new message has no text (e.g. a photo/sticker), it
// came from a different chat, or the request failed - check the log to
// tell those apart. Doesn't interpret `out_text` at all - matching it
// against "/status" or any other command is up to your own code.
bool telegram_poll_message(char *out_text, size_t out_cap);

#ifdef __cplusplus
}
#endif
