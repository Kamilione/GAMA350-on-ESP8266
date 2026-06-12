/*
 * This file is part of the dsmr_custom ESPHome component.
 *
 * This file is inspired by or based on the original ESPHome DSMR component,
 * available at: https://github.com/esphome/esphome/tree/dev/esphome/components/dsmr
 *
 * Modifications and new code are Copyright (c) 2025 (Niko Paulanne).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file dsmr.h
 * @brief Header file for the Dsmr (dsmr_custom) ESPHome component hub.
 * @details This component provides enhanced P1 port reading capabilities, featuring
 * user-definable OBIS code sensors, support for encrypted telegrams, and a
 * sensor override mechanism. Its architecture is
 * inspired by the native ESPHome DSMR component, but it has been specifically
 * implemented to support custom OBIS sensors and to interact with a modified
 * local parser for enhanced compatibility.
 * @author Niko Paulanne
 * @date June 7, 2025
 */

    #ifndef DSMR_CUSTOM_HUB_DSMR_H // Unique include guard for your hub component
    #define DSMR_CUSTOM_HUB_DSMR_H

    #if defined(USE_ARDUINO) || defined(USE_ESP_IDF) // Guard to ensure code is compiled for supported platforms.

    #include "esphome/core/component.h"
    #include "esphome/components/sensor/sensor.h"
    #include "esphome/components/text_sensor/text_sensor.h"
    #include "esphome/components/uart/uart.h"
    #include "esphome/core/hal.h"      // For hardware abstraction layer utilities (e.g., GPIOPin).
    #include "esphome/core/log.h"      // For ESP_LOGx logging macros.
    #include "esphome/core/defines.h"  // For common ESPHome defines.
    #include "esphome/core/optional.h" // For esphome::optional

    // Corrected includes for flattened parser structure
    #include "parser.h"
    #include "fields.h"
    #include "util.h"
    #include "crc16.h"

    #include <vector>
    #include <string>
    #include <cmath>
    #include <cstdlib>
    #include <map>

    namespace esphome {
    namespace dsmr_custom {

    using namespace ::dsmr::fields;

    #if !defined(DSMR_CUSTOM_SENSOR_LIST) && !defined(DSMR_CUSTOM_TEXT_SENSOR_LIST)
    #define DSMR_CUSTOM_TEXT_SENSOR_LIST(F, SEP) F(identification)
    #endif

    #if defined(DSMR_CUSTOM_SENSOR_LIST) && defined(DSMR_CUSTOM_TEXT_SENSOR_LIST)
    #define DSMR_CUSTOM_BOTH ,
    #else
    #define DSMR_CUSTOM_BOTH
    #endif

    #ifndef DSMR_CUSTOM_SENSOR_LIST
    #define DSMR_CUSTOM_SENSOR_LIST(F, SEP)
    #endif

    #ifndef DSMR_CUSTOM_TEXT_SENSOR_LIST
    #define DSMR_CUSTOM_TEXT_SENSOR_LIST(F, SEP)
    #endif

    #define DSMR_CUSTOM_DATA_SENSOR(s) s
    #define DSMR_CUSTOM_COMMA ,

    using MyData = ::dsmr::ParsedData<DSMR_CUSTOM_TEXT_SENSOR_LIST(DSMR_CUSTOM_DATA_SENSOR, DSMR_CUSTOM_COMMA)
                                          DSMR_CUSTOM_BOTH DSMR_CUSTOM_SENSOR_LIST(DSMR_CUSTOM_DATA_SENSOR, DSMR_CUSTOM_COMMA)>;

    enum class CustomObisSensorType {
      NUMERIC,
      TEXT
    };

    /**
     * @brief Telegram reception/decoding method.
     * @details PLAIN and ENCRYPTED preserve the original behaviour (selected
     * implicitly by the presence of a decryption key). POLAND_STOEN enables
     * support for the Elgama GAMA 350 meter (Stoen Operator, Poland), which
     * wraps an AES-128-GCM encrypted DLMS payload in a DSMR-style envelope.
     */
    enum class Method : uint8_t {
      PLAIN = 0,
      ENCRYPTED = 1,
      POLAND_STOEN = 2,
    };

    struct CustomObisSensorDefinition {
      std::string obis_code_str;
      esphome::sensor::Sensor *numeric_sensor_ptr{nullptr};
      esphome::text_sensor::TextSensor *text_sensor_ptr{nullptr};
      CustomObisSensorType type;
      float last_published_float_value{NAN};
      std::string last_published_text_value{""};
      uint32_t last_publish_time{0};
    };

    class Dsmr : public Component, public uart::UARTDevice {
     public:
      Dsmr(uart::UARTComponent *uart, bool crc_check);

      void setup() override;
      void loop() override;
      void dump_config() override;
      float get_setup_priority() const override { return esphome::setup_priority::LATE; }

      bool parse_telegram();
      void publish_sensors(MyData &data);

      void set_decryption_key(const std::string &decryption_key);
      void set_method(const std::string &method) {
        if (method == "poland_stoen") {
          this->method_ = Method::POLAND_STOEN;
        } else if (method == "encrypted") {
          this->method_ = Method::ENCRYPTED;
        } else {
          this->method_ = Method::PLAIN;
        }
      }
      // Optional 8-byte DLMS system title (16 hex chars) used as the first
      // half of the AES-GCM IV when the meter sends an empty system title in
      // the frame (Poland_STOEN). Defaults to zeros when unset.
      void set_system_title(const std::string &system_title_hex) {
        this->system_title_.clear();
        if (system_title_hex.length() == 16) {
          for (int i = 0; i < 8; i++) {
            char hex_pair[3] = {system_title_hex[i * 2],
                                system_title_hex[i * 2 + 1], '\0'};
            this->system_title_.push_back(
                static_cast<uint8_t>(std::strtoul(hex_pair, nullptr, 16)));
          }
        }
      }
      void set_max_telegram_length(size_t length) { this->max_telegram_len_ = length; }
      void set_request_pin(GPIOPin *request_pin) { this->request_pin_ = request_pin; }
      void set_request_interval(uint32_t interval) { this->request_interval_ = interval; }
      void set_receive_timeout(uint32_t timeout) { this->receive_timeout_ = timeout; }

      #define DSMR_SET_STANDARD_SENSOR(s) \
        void set_##s(sensor::Sensor *sensor) { \
          s_##s##_ = sensor; \
          if (sensor != nullptr) { \
            this->standard_numeric_sensor_pointers_[#s] = &this->s_##s##_; \
          } else { \
            this->standard_numeric_sensor_pointers_.erase(#s); \
          } \
        }
      DSMR_CUSTOM_SENSOR_LIST(DSMR_SET_STANDARD_SENSOR, )

      #define DSMR_SET_STANDARD_TEXT_SENSOR(s) \
        void set_##s(text_sensor::TextSensor *sensor) { \
          s_##s##_ = sensor; \
          if (sensor != nullptr) { \
            this->standard_text_sensor_pointers_[#s] = &this->s_##s##_; \
          } else { \
            this->standard_text_sensor_pointers_.erase(#s); \
          } \
        }
      DSMR_CUSTOM_TEXT_SENSOR_LIST(DSMR_SET_STANDARD_TEXT_SENSOR, )

      void set_telegram(text_sensor::TextSensor *sensor) { s_telegram_ = sensor; }

      void add_custom_numeric_sensor(const std::string &obis_code, esphome::sensor::Sensor *sens);
      void add_custom_text_sensor(const std::string &obis_code, esphome::text_sensor::TextSensor *sens);

     protected:
      void receive_telegram_();
      void receive_encrypted_telegram_();
      void reset_telegram_();

      // Poland_STOEN (Elgama GAMA 350) support, implemented in dsmr_stoen.cpp.
      void stoen_setup_();
      void stoen_reset_telegram_();
      void receive_stoen_telegram_();
      void process_stoen_telegram_();
      bool decrypt_stoen_telegram_();
      bool available_within_timeout_();
      bool request_interval_reached_();
      bool receive_timeout_reached_();

      void process_line_for_custom_sensors(const char *line_buffer, size_t length);
      optional<float> parse_numeric_value_from_string(const std::string &value_str);
      std::string parse_text_value_from_string(const std::string &value_str);

      void initialize_standard_sensor_obis_map_();

      uint32_t request_interval_{0};
      GPIOPin *request_pin_{nullptr};
      uint32_t last_request_time_{0};
      bool requesting_data_{false};
      bool ready_to_request_data_();
      void start_requesting_data_();
      void stop_requesting_data_();

      uint32_t receive_timeout_{200};
      size_t max_telegram_len_{1500};
      char *telegram_{nullptr};
      size_t bytes_read_{0};
      uint8_t *crypt_telegram_{nullptr};
      size_t crypt_telegram_len_{0};
      size_t crypt_bytes_read_{0};
      uint32_t last_read_time_{0};
      bool header_found_{false};
      bool footer_found_{false};

      text_sensor::TextSensor *s_telegram_{nullptr};

      #define DSMR_DECLARE_STANDARD_SENSOR(s) sensor::Sensor *s_##s##_{nullptr};
      DSMR_CUSTOM_SENSOR_LIST(DSMR_DECLARE_STANDARD_SENSOR, )
      #define DSMR_DECLARE_STANDARD_TEXT_SENSOR(s) text_sensor::TextSensor *s_##s##_{nullptr};
      DSMR_CUSTOM_TEXT_SENSOR_LIST(DSMR_DECLARE_STANDARD_TEXT_SENSOR, )

      std::vector<uint8_t> decryption_key_{};
      std::vector<uint8_t> system_title_{};
      bool crc_check_{true};

      Method method_{Method::PLAIN};

      // Poland_STOEN buffers and state. All three buffers (raw RX, encrypted
      // body, decrypted output) are sized from max_telegram_length, so the
      // existing YAML option is the single knob for telegram capacity. The
      // raw telegram must fit max_telegram_length anyway, because the
      // envelope and body are staged in telegram_ during parsing. A complete
      // GAMA 350 telegram is ~583 bytes, so max_telegram_length: 1024 is
      // ample. Buffers are only allocated when method: Poland_STOEN is set.
      static constexpr size_t STOEN_HEADER_MAX_LEN = 20;
      static constexpr size_t STOEN_FOOTER_MAX_LEN = 20;
      static constexpr size_t STOEN_GCM_TAG_LEN = 12;

      size_t stoen_buffer_size_{0};
      uint8_t *stoen_rx_buffer_{nullptr};
      size_t stoen_rx_len_{0};
      uint32_t stoen_last_receive_time_{0};
      char *stoen_header_{nullptr};
      bool stoen_header_completed_{false};
      bool stoen_empty_line_completed_{false};
      size_t stoen_body_pos_{0};
      uint8_t *stoen_body_{nullptr};
      size_t stoen_body_bytes_{0};
      char *stoen_footer_{nullptr};
      bool stoen_footer_completed_{false};
      char *stoen_decrypted_{nullptr};
      size_t stoen_decrypted_bytes_{0};

      std::vector<CustomObisSensorDefinition> custom_obis_definitions_;

      // CORRECTION: Define debounce constants as static constexpr members of the class
      static constexpr uint32_t CUSTOM_SENSOR_MIN_PUBLISH_INTERVAL_MS = 5000;
      static constexpr float CUSTOM_SENSOR_FLOAT_TOLERANCE = 0.001f;

      std::map<std::string, std::string> standard_sensor_to_obis_map_;
      std::map<std::string, esphome::sensor::Sensor**> standard_numeric_sensor_pointers_;
      std::map<std::string, esphome::text_sensor::TextSensor**> standard_text_sensor_pointers_;
    };

    }  // namespace dsmr_custom
    }  // namespace esphome

    #endif  // USE_ARDUINO
    #endif // DSMR_CUSTOM_HUB_DSMR_H
    
