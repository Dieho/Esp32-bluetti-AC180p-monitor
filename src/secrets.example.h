// =============================================================================
// secrets.example.h
// =============================================================================
// Template for secrets.h. Copy this file to secrets.h (same directory) and
// fill in your own values:
//
//     cp src/secrets.example.h src/secrets.h
//
// secrets.h is gitignored and never committed - this example file is, so
// anyone cloning the project (including future you, setting up a new
// Bluetti station or a new Telegram bot) knows what to create.
// =============================================================================

#pragma once

// Your WiFi network.
#define WIFI_SSID "your-wifi-ssid"
#define WIFI_PASS "your-wifi-password"

// Your Bluetti station's REAL BLE MAC address - use the ESP32 itself to find
// it (flash the project and watch the serial log's device-scan output; see
// the notes in bluetti_ble.cpp), not what a phone app shows you, since
// macOS/iOS hide the real address for privacy. BLUETTI_USE_ENCRYPTION should
// be true for most newer Bluetti stations.
#define BLUETTI_MAC_ADDRESS "AA:BB:CC:DD:EE:FF"
#define BLUETTI_USE_ENCRYPTION true

// Your Telegram bot's token (from @BotFather) and the numeric chat id it
// should talk to - see the setup notes at the top of telegram_bot.h for how
// to get both.
#define TELEGRAM_BOT_TOKEN "123456789:AAExampleTokenTextGoesHere"
#define TELEGRAM_CHAT_ID   "987654321"
