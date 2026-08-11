#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "bluetti_ble.h"
#include <esp_timer.h>
#include <driver/gpio.h>
#include "telegram_bot.h"
#include "esp_system.h"
#include "main.h"

// WiFi/Bluetti/Telegram credentials live in secrets.h, which is gitignored -
// see secrets.example.h for the template to copy if this file doesn't exist
// yet (defines WIFI_SSID, WIFI_PASS, BLUETTI_MAC_ADDRESS,
// BLUETTI_USE_ENCRYPTION, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID).
#include "secrets.h"

static const char *TAG = "wifi_station";

// An event group is a way for tasks to signal/wait on flags -
// think of it loosely like a ManualResetEvent in C#.
static EventGroupHandle_t wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static int retry_count = 0;
#define MAX_RETRIES 5

// This callback fires whenever WiFi or IP-related events happen.
// It's the "event handler" - registered once, called by the WiFi/network
// internals whenever something relevant occurs.
static void event_handler(void* arg, esp_event_base_t event_base,
                           int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        ESP_LOGI(TAG, "WiFi started, connecting...");
        esp_wifi_connect();
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (retry_count < MAX_RETRIES) {
            esp_wifi_connect();
            retry_count++;
            ESP_LOGI(TAG, "Retrying connection... (%d/%d)", retry_count, MAX_RETRIES);
        } else {
            xEventGroupSetBits(wifi_event_group, WIFI_FAIL_BIT);
            ESP_LOGW(TAG, "Failed to connect after %d attempts", MAX_RETRIES);
        }
    }
    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "Got IP address: " IPSTR, IP2STR(&event->ip_info.ip));
        retry_count = 0;
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void wifi_init_station(void)
{
    wifi_event_group = xEventGroupCreate();

    // Initialize the underlying TCP/IP stack and event loop
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    // Subscribe our event_handler to both WiFi and IP events
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL));

    wifi_config_t wifi_config = {};
    strcpy((char*)wifi_config.sta.ssid, WIFI_SSID);
    strcpy((char*)wifi_config.sta.password, WIFI_PASS);
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "wifi_init_station finished, waiting for connection...");

    // Block here until we either connect or exhaust retries -
    // similar in spirit to `await someTask` in C#, but implemented
    // via a FreeRTOS event group instead of the language runtime.
    EventBits_t bits = xEventGroupWaitBits(wifi_event_group,
            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
            pdFALSE, pdFALSE, portMAX_DELAY);

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "Connected to WiFi successfully");
    } else if (bits & WIFI_FAIL_BIT) {
        ESP_LOGE(TAG, "Failed to connect to WiFi");
    }
}
#define BUTTON_PIN GPIO_NUM_0

extern "C" void app_main(void)
{
    // Logged first, before anything else can fail/reboot us again - tells
    // us definitively WHY the previous boot ended, instead of guessing from
    // symptoms in the serial log (e.g. ESP_RST_BROWNOUT = the power supply
    // sagged under load, ESP_RST_PANIC = an actual crash, ESP_RST_TASK_WDT
    // = a task got stuck long enough to trip the watchdog, etc).
    esp_reset_reason_t reset_reason = esp_reset_reason();
    if (reset_reason == ESP_RST_BROWNOUT) {
        ESP_LOGW(TAG, "Last reset was a BROWNOUT (reason=%d) - the power supply likely sagged under load", reset_reason);
    } else if (reset_reason != ESP_RST_POWERON) {
        ESP_LOGW(TAG, "Last reset was NOT a normal power-on (reason=%d) - see esp_reset_reason_t for what this code means", reset_reason);
    }

    // NVS (non-volatile storage) is flash-backed key-value storage.
    // WiFi driver uses it internally to store calibration data, so it
    // must be initialized first even though we don't touch it directly.
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Quiet down NimBLE's own per-operation logging (e.g. "GATT procedure
    // initiated: write; att_handle=... len=..."), which otherwise fires
    // constantly during scanning/connecting/every BLE read. WARN still
    // shows real problems (failed writes, disconnects); it just drops the
    // routine INFO-level noise.
    esp_log_level_set("NimBLE", ESP_LOG_WARN);

    wifi_init_station();
    telegram_bot_init(TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID);

    gpio_reset_pin(BUTTON_PIN);
    gpio_set_direction(BUTTON_PIN, GPIO_MODE_INPUT);
    gpio_set_pull_mode(BUTTON_PIN, GPIO_PULLUP_ONLY);

    int64_t last_check_time = 0;
    int64_t last_press_time = 0;
    const int64_t check_interval_us = 10000 * 1000;   // 10s interval for checking Bluetti data
    const int64_t debounce_us = 200 * 1000;         // 200ms debounce
    bool button_was_pressed = false;
    float last_notified_battery_soc = -1.0f; // -1 = "never notified yet"
    bool ac_lost_notified = false;
    bool zero_battery_notified = false;
    bool sendDebugTgMsg = false;

    // --- Bluetti station demo ---------------------------------------------
    // See src/bluetti_ble.h/.cpp for the full implementation + important
    // notes about what's untested. This just shows the three functions in
    // action: connect once, poll get_all_data() every 10s, and clean up
    // with stop_connection() if the connection ever needs to end.
    if (connect_to_bluetti(BLUETTI_MAC_ADDRESS, BLUETTI_USE_ENCRYPTION)) {
        ESP_LOGI(TAG, "Connected to Bluetti station");

        bluetti_data_t data;
        while (1) {
            if(last_check_time == 0 || (esp_timer_get_time() - last_check_time) > check_interval_us) {
                if (get_all_data(&data)) {
                    ESP_LOGI(TAG, "get_all_data() succeeded this cycle");
                    // ESP_LOGI(TAG, "Battery=%.0f%% AC_in=%.0fW AC_out=%.0fW DC_in=%.0fW DC_out=%.0fW V_in=%.1fV",
                    //         data.battery_soc, data.ac_input_power, data.ac_output_power,
                    //         data.dc_input_power, data.dc_output_power, data.ac_input_voltage);
                } else {
                    ESP_LOGW(TAG, "get_all_data() failed this cycle, will reconnect");
                    if(sendDebugTgMsg == true)
                    {
                        telegram_send_message("⚠️ Connection to Bluetti station lost - attempting to reconnect");
                    }
                    ReconnectOrRestart(sendDebugTgMsg);
                    get_all_data(&data); // try again after reconnecting, so we don't send stale data
                    if(sendDebugTgMsg == true)
                    {
                        telegram_send_messagef("🔋 Battery=%.0f%% AC in=%.0fW AC out=%.0fW DC in=%.0fW DC out=%.0fW V in=%.1fV",
                            data.battery_soc, data.ac_input_power, data.ac_output_power,
                            data.dc_input_power, data.dc_output_power, data.ac_input_voltage);
                    }

                }
                
                
                // Edge-triggered, same idea as button_was_pressed below: only
                // fire once per 20% threshold crossing (or per AC-loss event),
                // not once per 10s poll cycle for as long as the condition
                // happens to still be true.
                if ((int16_t)data.battery_soc % 20 == 0 && data.battery_soc != last_notified_battery_soc) {
                    telegram_send_messagef("🔋 Battery: %.0f%%", data.battery_soc);
                    last_notified_battery_soc = data.battery_soc;
                }
                // if (data.ac_input_power == 0.0f && data.ac_output_power != 0.0f) {
                //     if (!ac_lost_notified) {
                //         telegram_send_message("AC input lost - running on battery");
                //         ac_lost_notified = true;
                //     }
                // } 
                if (data.ac_input_voltage < 200.0f) { // arbitrary threshold for "AC input lost"
                    if (!ac_lost_notified) {
                        telegram_send_message("⚠️ AC input lost - running on battery");
                        ac_lost_notified = true;
                    }
                }
                else {
                    ac_lost_notified = false;
                }

                if(ac_lost_notified && data.ac_input_voltage > 200.0f) {
                   telegram_send_message("✅ AC input restored");
                        ac_lost_notified = false;
                }

                // if(ac_lost_notified && data.ac_input_power > 0.0f) {
                //    telegram_send_message("AC input restored");
                //         ac_lost_notified = false;
                // }

                // NOTE: this used to call ReconnectOrRestart() here, on the
                // theory that battery_soc==0 meant the connection was lost.
                // It isn't - get_all_data() already succeeded this cycle
                // (that's a real register read, not a stale/lost value), so
                // restarting the ESP32 can't change what the station
                // reports. Every test run showed the exact same shape:
                // connects fine, battery reads 0% on the very first read
                // after the handshake, restart, repeat forever - an
                // infinite loop that never actually recovers anything and
                // just re-sends this alert every ~10s. Alerting is still
                // useful (0% - or a bad first read - is worth knowing
                // about), so that stays; only fire it once per occurrence,
                // same pattern as ac_lost_notified above.
                if (data.battery_soc == 0.0f) {
                    if (!zero_battery_notified) {
                        telegram_send_message("⚠️ Battery reading 0% - station may be empty, or this may be a bad reading right after connecting");
                        zero_battery_notified = true;
                    }
                } else {
                    zero_battery_notified = false;
                }

                char msg[128];
                if (telegram_poll_message(msg, sizeof(msg))) {
                    if (strcmp(msg, "/status") == 0) {
                        ESP_LOGW(TAG, "Status called");
                        telegram_send_messagef("🔋 Battery=%.0f%% AC in=%.0fW AC out=%.0fW DC in=%.0fW DC out=%.0fW V in=%.1fV Device=%s",
                            data.battery_soc, data.ac_input_power, data.ac_output_power,
                            data.dc_input_power, data.dc_output_power, data.ac_input_voltage,
                            data.device_type);
                    }
                    if (strcmp(msg, "/restart") == 0) {
                        ESP_LOGW(TAG, "restart called");
                        // esp_restart() never returns, which means Telegram
                        // never gets a follow-up getUpdates request telling
                        // it we've seen this /restart message - so on next
                        // boot it hands us the same command again and we
                        // restart again, forever. One throwaway poll here
                        // (result intentionally ignored) commits our
                        // already-advanced offset to Telegram's server
                        // BEFORE we reboot, so this /restart won't come
                        // back to us a second time.
                        char discard[8];
                        telegram_poll_message(discard, sizeof(discard));
                        esp_restart();
                    }
                    if(strcasecmp(msg, "/debug") == 0) {
                        ESP_LOGW(TAG, "debug called");
                        sendDebugTgMsg = !sendDebugTgMsg;
                        telegram_send_messagef("🐛 Debug messages %s", sendDebugTgMsg ? "enabled" : "disabled");
                    }
                    if (strcasecmp(msg, "/switchAC") == 0) {
                        ESP_LOGW(TAG, "switchAC called");
                        bool new_state = false;
                        if (toggle_ac_output(&new_state)) {
                            telegram_send_messagef("✅ AC output switched %s", new_state ? "ON" : "OFF");
                        } else {
                            telegram_send_message("❌ Failed to switch AC output - see device log");
                        }
                    }
                    if (strcasecmp(msg, "/switchDC") == 0) {
                        ESP_LOGW(TAG, "switchDC called");
                        bool new_state = false;
                        if (toggle_dc_output(&new_state)) {
                            telegram_send_messagef("✅ DC output switched %s", new_state ? "ON" : "OFF");
                        } else {
                            telegram_send_message("❌ Failed to switch DC output - see device log");
                        }
                    }
                }

                last_check_time = esp_timer_get_time();
            }

            if(last_press_time == 0 || (esp_timer_get_time() - last_press_time) > debounce_us) {
                bool button_is_pressed = (gpio_get_level(BUTTON_PIN) == 0);
                if (button_is_pressed && !button_was_pressed) {
                    telegram_send_messagef("🔋 Battery=%.0f%% AC in=%.0fW AC out=%.0fW DC in=%.0fW DC out=%.0fW V in=%.1fV",
                            data.battery_soc, data.ac_input_power, data.ac_output_power,
                            data.dc_input_power, data.dc_output_power, data.ac_input_voltage);
                    ESP_LOGI(TAG, "Battery=%.0f%% AC_in=%.0fW AC_out=%.0fW DC_in=%.0fW DC_out=%.0fW V_in=%.1fV",
                            data.battery_soc, data.ac_input_power, data.ac_output_power,
                            data.dc_input_power, data.dc_output_power, data.ac_input_voltage);
                }
                button_was_pressed = button_is_pressed;
                last_press_time = esp_timer_get_time();
            }
            vTaskDelay(pdMS_TO_TICKS(10));
        }

        stop_connection();
    } else {
        ESP_LOGE(TAG, "Failed to connect to Bluetti station - check the MAC "
                       "address and see the notes at the top of bluetti_ble.cpp");
    }

    // while (1) {
    //     vTaskDelay(pdMS_TO_TICKS(10000));
    //     ESP_LOGI(TAG, "Still alive...");
    // }
}

void ReconnectOrRestart(bool sendMsg)
{
    // stop_connection() now actually waits for the BLE link to finish
    // tearing down before returning (see its comment in bluetti_ble.cpp) -
    // that race is why reconnecting used to fail here. Falls back to a
    // full restart only if the reconnect attempt itself fails.
    stop_connection();
    if (connect_to_bluetti(BLUETTI_MAC_ADDRESS, BLUETTI_USE_ENCRYPTION))
    {
        ESP_LOGI(TAG, "Reconnected to Bluetti station");
        if (sendMsg == true)
        {telegram_send_message("✅ Reconnected to Bluetti station");}
    }
    else
    {
        telegram_send_message("❌ Failed to reconnect to Bluetti station. Restarting...");
        ESP_LOGE(TAG, "Failed to reconnect to Bluetti station. Restarting...");
        esp_restart();
    }
} /*
 #include <stdio.h>
 #include "freertos/FreeRTOS.h"
 #include "freertos/task.h"
 #include "driver/gpio.h"
 #include "esp_log.h"
 #include "esp_timer.h"

 #define LED_PIN GPIO_NUM_2
 #define BUTTON_PIN GPIO_NUM_0
 static const char *TAG = "toggle_blink";

 extern "C" void app_main(void)
 {
     gpio_reset_pin(LED_PIN);
     gpio_set_direction(LED_PIN, GPIO_MODE_OUTPUT);

     gpio_reset_pin(BUTTON_PIN);
     gpio_set_direction(BUTTON_PIN, GPIO_MODE_INPUT);
     gpio_set_pull_mode(BUTTON_PIN, GPIO_PULLUP_ONLY);

     bool blinking = false;
     bool led_state = false;
     bool button_was_pressed = false;   // tracks previous state, for edge detection
     int64_t last_blink_time = 0;
     int64_t last_press_time = 0;
     const int64_t blink_interval_us = 500 * 1000;   // 500ms
     const int64_t debounce_us = 200 * 1000;         // 200ms debounce

     while (1) {
         int64_t now = esp_timer_get_time();   // microseconds since boot

         bool button_is_pressed = (gpio_get_level(BUTTON_PIN) == 0);

         // Detect the moment of press (transition from not-pressed to pressed)
         if (button_is_pressed && !button_was_pressed) {
             if (now - last_press_time > debounce_us) {  // ignore bounces/rapid re-triggers
                 blinking = !blinking;
                 ESP_LOGI(TAG, "Toggled blinking: %s", blinking ? "ON" : "OFF");
                 if (!blinking) {
                     gpio_set_level(LED_PIN, 0);  // make sure LED is off when stopped
                     led_state = false;
                 }
                 last_press_time = now;
             }
         }
         button_was_pressed = button_is_pressed;

         // Handle blinking without blocking (no vTaskDelay(500) here!)
         if (blinking && (now - last_blink_time > blink_interval_us)) {
             ESP_LOGI(TAG, "led_state: %s", led_state ? "ON" : "OFF");
             led_state = true;//!led_state;
             gpio_set_level(LED_PIN, led_state);
             last_blink_time = now;
         }

         vTaskDelay(pdMS_TO_TICKS(10));  // short delay, keeps button checks responsive
     }
 }
     */