/*
 * This file is part of the dsmr_custom ESPHome component.
 *
 * Poland_STOEN (Elgama GAMA 350, Stoen Operator) telegram support.
 * Ported from the BAJO_STOEN branch by BJozwiak (ESP32/ESP-IDF) to run on
 * ESP8266 (Arduino framework) as well. The ESP-IDF-only debug facilities
 * (UDP sockets via sys/socket.h) were removed; multi-byte fields from the
 * telegram are assembled manually byte-by-byte, so no ntohl/htonl or lwIP
 * headers are required.
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
 * @file dsmr_stoen.cpp
 * @brief Implementation of `method: Poland_STOEN` for the dsmr_custom hub.
 * @details The Elgama GAMA 350 (Stoen Operator, Poland) sends a DSMR-style
 * envelope with an encrypted DLMS payload:
 *
 *   /EGM5G35\r\n\r\n            ASCII identification header
 *   00 82 02 30 ...             0x00 (empty system title), BER length 0x0230
 *   <AES-128-GCM ciphertext>    ~560 bytes
 *   !XXXX\r\n                   footer with CRC characters
 *
 * A complete telegram is ~583 bytes (564-byte body). The receive buffers are
 * sized from the existing max_telegram_length YAML option, so 1024 leaves
 * ample headroom.
 * The payload is decrypted with AES-128-GCM; the IV is built from the system
 * title (zeros when the title is empty) and the 4-byte frame counter. The GCM
 * tag is not verified because the DLMS additional authenticated data is not
 * available - this matches the reference BAJO_STOEN implementation.
 */

#if defined(USE_ARDUINO) ||                                                    \
    defined(USE_ESP_IDF) // Guard for supported platforms

#include "dsmr.h"
#include "esphome/core/helpers.h" // format_hex for the VERBOSE body dump
#include "esphome/core/log.h"

// Cryptography libraries for AES-GCM decryption
#ifdef USE_ARDUINO
// rweather/Crypto: software AES-128-GCM, works on ESP8266 and ESP32 Arduino.
#include <AES.h>
#include <GCM.h>
#else
// ESP-IDF: Use hardware-accelerated MbedTLS wrapper
#include "dsmr_crypto.h"
#endif

#include <cstring>

namespace esphome {
namespace dsmr_custom {

static const char *const TAG = "dsmr_custom.stoen";

void Dsmr::stoen_setup_() {
  ESP_LOGCONFIG(
      TAG, "Setting up Poland_STOEN (Elgama GAMA 350) telegram support...");

  // One size for all three buffers, derived from max_telegram_length: the
  // raw telegram has to fit telegram_ (same option) during parsing anyway,
  // so a single YAML knob governs the whole pipeline.
  this->stoen_buffer_size_ = this->max_telegram_len_ + 1;
  ESP_LOGCONFIG(TAG, "  STOEN buffers: 3 x %zu bytes (from max_telegram_length)",
                this->stoen_buffer_size_);
  this->stoen_rx_buffer_ = new uint8_t[this->stoen_buffer_size_];
  this->stoen_body_ = new uint8_t[this->stoen_buffer_size_];
  this->stoen_decrypted_ = new char[this->stoen_buffer_size_];
  this->stoen_header_ = new char[STOEN_HEADER_MAX_LEN + 1];
  this->stoen_footer_ = new char[STOEN_FOOTER_MAX_LEN + 1];
  if (this->stoen_rx_buffer_ == nullptr || this->stoen_body_ == nullptr ||
      this->stoen_decrypted_ == nullptr || this->stoen_header_ == nullptr ||
      this->stoen_footer_ == nullptr) {
    ESP_LOGE(TAG, "Failed to allocate Poland_STOEN buffers!");
    this->mark_failed();
    return;
  }
  this->stoen_header_[0] = '\0';
  this->stoen_footer_[0] = '\0';
  this->stoen_decrypted_[0] = '\0';

  // In Poland_STOEN mode receive_timeout is the idle gap that marks the end
  // of a telegram. The GAMA 350 transmits about once per second, so a value
  // at or above that interval means the gap is never detected and telegrams
  // pile up in the receive buffer until it overflows.
  if (this->receive_timeout_ > 500) {
    ESP_LOGW(TAG,
             "receive_timeout (%ums) is too long for Poland_STOEN: it is the "
             "idle gap that ends a telegram, and the meter sends every ~1s. "
             "Telegrams will accumulate and overflow the receive buffer. Use "
             "200-500ms (default: 200ms).",
             this->receive_timeout_);
  }

  if (this->decryption_key_.empty()) {
    ESP_LOGE(TAG, "method: Poland_STOEN requires a valid decryption_key!");
    this->mark_failed();
  }
}

void Dsmr::stoen_reset_telegram_() {
  this->stoen_header_completed_ = false;
  this->stoen_empty_line_completed_ = false;
  this->stoen_footer_completed_ = false;
  this->stoen_body_pos_ = 0;
  this->stoen_body_bytes_ = 0;
  this->stoen_decrypted_bytes_ = 0;
  if (this->stoen_header_ != nullptr) {
    this->stoen_header_[0] = '\0';
  }
  if (this->stoen_footer_ != nullptr) {
    this->stoen_footer_[0] = '\0';
  }
  if (this->stoen_body_ != nullptr) {
    this->stoen_body_[0] = 0;
  }
  if (this->stoen_decrypted_ != nullptr) {
    this->stoen_decrypted_[0] = '\0';
  }
}

void Dsmr::receive_stoen_telegram_() {
  // Read everything the UART has buffered in one go; the telegram boundary is
  // detected by a silence gap on the line, not byte-by-byte.
  int avail = this->available();
  if (avail > 0) {
    size_t to_read = static_cast<size_t>(avail);
    if (this->stoen_rx_len_ + to_read > this->stoen_buffer_size_) {
      ESP_LOGW(TAG,
               "STOEN RX buffer overflow (%zu buffered + %zu incoming > %zu). "
               "Discarding buffered data. Consider raising "
               "max_telegram_length.",
               this->stoen_rx_len_, to_read, this->stoen_buffer_size_);
      this->stoen_rx_len_ = 0;
      if (to_read > this->stoen_buffer_size_) {
        while (this->available()) {
          this->read();
        }
        this->stoen_last_receive_time_ = millis();
        return;
      }
    }
    this->read_array(this->stoen_rx_buffer_ + this->stoen_rx_len_, to_read);
    this->stoen_rx_len_ += to_read;
    this->stoen_last_receive_time_ = millis();
  }

  // The GAMA 350 sends the telegram as one burst; once the line has been
  // silent for the receive timeout, the buffered data is a complete telegram.
  const uint32_t idle_timeout =
      this->receive_timeout_ > 0 ? this->receive_timeout_ : 200;
  if (this->stoen_last_receive_time_ != 0 && this->stoen_rx_len_ > 0 &&
      (millis() - this->stoen_last_receive_time_) > idle_timeout) {
    this->reset_telegram_();
    this->process_stoen_telegram_();
    this->stoen_last_receive_time_ = 0;
    this->stoen_rx_len_ = 0;
  }
}

void Dsmr::process_stoen_telegram_() {
  const size_t len = this->stoen_rx_len_;
  const uint8_t *rx = this->stoen_rx_buffer_;
  const uint32_t process_start = millis();
  size_t x = 0;

  while (x < len && !this->stoen_footer_completed_) {
    const char c = static_cast<char>(rx[x]);

    // Worst-case write per iteration is 7 bytes (footer) plus terminator.
    if (this->bytes_read_ + 8 >= this->max_telegram_len_) {
      ESP_LOGE(TAG,
               "Error: STOEN telegram larger than buffer (%zu bytes). "
               "Discarding.",
               this->max_telegram_len_);
      this->reset_telegram_();
      this->stop_requesting_data_();
      return;
    }

    if (!this->header_found_) {
      if (c == '/') {
        ESP_LOGV(TAG, "Header of STOEN telegram found ('/').");
        this->reset_telegram_();
        this->header_found_ = true;
        this->last_read_time_ = millis();
        // Fall through: '/' is stored as the first header byte below.
      } else {
        x++;
        continue;
      }
    }

    if (!this->stoen_header_completed_) {
      // Identification line, e.g. "/EGM5G35", terminated by CR LF.
      if (c == '\r' && x + 1 < len) {
        const char e = static_cast<char>(rx[x + 1]);
        if (e == '\n') {
          this->telegram_[this->bytes_read_] = '\0';
          strncpy(this->stoen_header_, this->telegram_, STOEN_HEADER_MAX_LEN);
          this->stoen_header_[STOEN_HEADER_MAX_LEN] = '\0';
          this->stoen_header_completed_ = true;
          ESP_LOGV(TAG, "STOEN header completed: '%s'.", this->stoen_header_);
        }
        this->telegram_[this->bytes_read_++] = c;
        this->telegram_[this->bytes_read_++] = e;
        x += 2;
      } else {
        this->telegram_[this->bytes_read_++] = c;
        x++;
      }
      continue;
    }

    if (!this->stoen_empty_line_completed_) {
      // Empty line (CR LF) between the header and the encrypted body.
      if (c == '\r' && x + 1 < len) {
        const char e = static_cast<char>(rx[x + 1]);
        this->telegram_[this->bytes_read_++] = c;
        this->telegram_[this->bytes_read_++] = e;
        x += 2;
        if (e == '\n') {
          this->stoen_empty_line_completed_ = true;
          this->stoen_body_pos_ = this->bytes_read_;
          ESP_LOGV(TAG, "STOEN body starts at telegram offset %zu.",
                   this->stoen_body_pos_);
        }
      } else {
        this->telegram_[this->bytes_read_++] = c;
        x++;
      }
      continue;
    }

    // Encrypted body until the footer: '!' CRC1 CRC2 CRC3 CRC4 CR LF.
    // A 0x21 ('!') byte can also occur inside the encrypted body, so the
    // footer is only accepted when the full pattern matches.
    if (c == '!' && x + 6 < len && rx[x + 5] == '\r' && rx[x + 6] == '\n') {
      this->stoen_footer_[0] = static_cast<char>(rx[x + 1]);
      this->stoen_footer_[1] = static_cast<char>(rx[x + 2]);
      this->stoen_footer_[2] = static_cast<char>(rx[x + 3]);
      this->stoen_footer_[3] = static_cast<char>(rx[x + 4]);
      this->stoen_footer_[4] = '\0';
      this->footer_found_ = true;
      this->stoen_footer_completed_ = true;
      ESP_LOGV(TAG, "STOEN footer found: '!%s'.", this->stoen_footer_);
      x += 7;
      break;
    }
    if (this->stoen_body_bytes_ + 1 >= this->stoen_buffer_size_) {
      ESP_LOGE(TAG, "STOEN body larger than %zu bytes. Discarding.",
               this->stoen_buffer_size_);
      this->reset_telegram_();
      this->stop_requesting_data_();
      return;
    }
    this->telegram_[this->bytes_read_++] = c;
    this->stoen_body_[this->stoen_body_bytes_++] = rx[x];
    x++;
  }

  if (!this->stoen_footer_completed_) {
    if (this->header_found_) {
      ESP_LOGW(TAG,
               "Incomplete STOEN telegram (%zu bytes buffered, no footer). "
               "Discarding.",
               len);
    } else {
      ESP_LOGV(TAG, "No STOEN telegram header in %zu buffered bytes.", len);
    }
    this->reset_telegram_();
    return;
  }

  this->stoen_body_[this->stoen_body_bytes_] = 0;
  this->telegram_[this->bytes_read_] = '\0';

  if (!this->decrypt_stoen_telegram_()) {
    this->reset_telegram_();
    this->stop_requesting_data_();
    return;
  }

  // Rebuild the telegram with the decrypted payload:
  //   <header>\r\n\r\n<decrypted body>!<CRC>\r\n
  const size_t footer_len = strlen(this->stoen_footer_);
  const size_t rebuilt_len = this->stoen_body_pos_ +
                             this->stoen_decrypted_bytes_ + 1 + footer_len + 2;
  if (rebuilt_len + 1 > this->max_telegram_len_) {
    ESP_LOGE(TAG,
             "Rebuilt STOEN telegram (%zu bytes) exceeds max_telegram_length "
             "(%zu).",
             rebuilt_len, this->max_telegram_len_);
    this->reset_telegram_();
    this->stop_requesting_data_();
    return;
  }
  memcpy(this->telegram_ + this->stoen_body_pos_, this->stoen_decrypted_,
         this->stoen_decrypted_bytes_);
  size_t pos = this->stoen_body_pos_ + this->stoen_decrypted_bytes_;
  this->telegram_[pos++] = '!';
  memcpy(this->telegram_ + pos, this->stoen_footer_, footer_len);
  pos += footer_len;
  this->telegram_[pos++] = '\r';
  this->telegram_[pos++] = '\n';
  this->telegram_[pos] = '\0';
  this->bytes_read_ = pos;

  ESP_LOGD(TAG, "STOEN telegram complete: %zu bytes (processing took %ums).",
           this->bytes_read_,
           static_cast<unsigned>(millis() - process_start));

  this->parse_telegram();
  this->reset_telegram_();
}

bool Dsmr::decrypt_stoen_telegram_() {
  if (this->decryption_key_.empty()) {
    ESP_LOGE(TAG, "Poland_STOEN telegram received but no decryption_key set!");
    return false;
  }

#ifdef ESPHOME_LOG_HAS_VERBOSE
  // Raw encrypted body dump for offline analysis with
  // scripts/try_decrypt.py (e.g. finding the right system_title).
  for (size_t i = 0; i < this->stoen_body_bytes_; i += 32) {
    const size_t n =
        this->stoen_body_bytes_ - i < 32 ? this->stoen_body_bytes_ - i : 32;
    ESP_LOGV(TAG, "BODY[%03zu]: %s", i,
             format_hex(this->stoen_body_ + i, n).c_str());
  }
#endif

  size_t system_title_length;
  if (this->stoen_body_[0] == 0x00) {
    // 0x00: empty system title (GAMA 350 / Stoen frames).
    system_title_length = 1;
  } else if (this->stoen_body_[0] == 0xDB) {
    // 0xDB: general-glo-ciphering, next byte is the system title length.
    system_title_length = static_cast<size_t>(this->stoen_body_[1]) + 2;
  } else {
    ESP_LOGE(TAG, "STOEN decryptor: unknown start byte 0x%02X.",
             this->stoen_body_[0]);
    return false;
  }

  const size_t ciphertext_offset = system_title_length + 8;
  if (this->stoen_body_bytes_ < ciphertext_offset + STOEN_GCM_TAG_LEN) {
    ESP_LOGE(TAG, "STOEN frame too short: %zu bytes.",
             this->stoen_body_bytes_);
    return false;
  }

  // 16-bit big-endian payload length following the BER 0x82 length prefix,
  // assembled manually (no ntohs / socket headers).
  const size_t len_info =
      (static_cast<size_t>(this->stoen_body_[system_title_length + 1]) << 8) |
      static_cast<size_t>(this->stoen_body_[system_title_length + 2]);

  // LEN_INFO covers: security byte + 4-byte frame counter + ciphertext +
  // GCM tag, hence the fixed overhead of 5 + 12 bytes.
  if (len_info <= 5 + STOEN_GCM_TAG_LEN) {
    ESP_LOGE(TAG, "STOEN LEN_INFO too small: %zu.", len_info);
    return false;
  }
  size_t ciphertext_len = len_info - 5;

  if (ciphertext_offset + ciphertext_len != this->stoen_body_bytes_) {
    ESP_LOGW(TAG,
             "STOEN frame length mismatch: expected %zu bytes from LEN_INFO, "
             "got %zu. Trying to decrypt anyway.",
             ciphertext_offset + ciphertext_len, this->stoen_body_bytes_);
  }
  ciphertext_len -= STOEN_GCM_TAG_LEN; // exclude the trailing GCM tag

  if (ciphertext_len >= this->stoen_buffer_size_ ||
      ciphertext_offset + ciphertext_len > this->stoen_body_bytes_) {
    ESP_LOGE(TAG, "STOEN ciphertext length (%zu) out of range.",
             ciphertext_len);
    return false;
  }

  // IV: 8 bytes of system title followed by the 4-byte frame counter. When
  // the frame carries an empty system title, use the configured
  // system_title: option if set, zeros otherwise (some meters use their
  // real, serial-derived system title internally without transmitting it).
  uint8_t iv[12] = {0};
  if (system_title_length > 8) {
    memcpy(iv, &this->stoen_body_[2], 8);
  } else if (this->system_title_.size() == 8) {
    memcpy(iv, this->system_title_.data(), 8);
  }
  memcpy(iv + 8, &this->stoen_body_[system_title_length + 4], 4);

  const uint8_t *ciphertext_ptr = &this->stoen_body_[ciphertext_offset];

  // The GCM tag cannot be verified: the DLMS additional authenticated data
  // (security byte + authentication key) is not available. This matches the
  // reference BAJO_STOEN implementation, which also skips tag verification.
#ifdef USE_ARDUINO
  // Arduino (ESP8266/ESP32): rweather/Crypto software AES-128-GCM.
  GCM<AES128> gcmaes128;
  gcmaes128.setKey(this->decryption_key_.data(), gcmaes128.keySize());
  gcmaes128.setIV(iv, sizeof(iv));
  gcmaes128.decrypt(reinterpret_cast<uint8_t *>(this->stoen_decrypted_),
                    ciphertext_ptr, ciphertext_len);
#else
  // ESP-IDF: hardware-accelerated MbedTLS wrapper, tag_len 0 skips the check
  // (a non-zero tag_len would zeroize the output on the expected mismatch).
  const uint8_t *tag_ptr =
      &this->stoen_body_[ciphertext_offset + ciphertext_len];
  int decrypt_result = dsmr_aes_gcm_decrypt(
      this->decryption_key_.data(), this->decryption_key_.size(), iv,
      sizeof(iv), ciphertext_ptr, ciphertext_len, tag_ptr, 0,
      reinterpret_cast<unsigned char *>(this->stoen_decrypted_));
  if (decrypt_result != 0) {
    ESP_LOGW(TAG, "STOEN decryption returned error code %d.", decrypt_result);
  }
#endif

  this->stoen_decrypted_[ciphertext_len] = '\0';
  this->stoen_decrypted_bytes_ = ciphertext_len;

  // Verdict: a correct key/IV yields ASCII OBIS lines, a wrong one yields
  // binary noise. Check the first bytes so a misconfiguration is visible in
  // the log instead of silently publishing garbage.
  size_t check_len = ciphertext_len < 32 ? ciphertext_len : 32;
  size_t printable = 0;
  for (size_t i = 0; i < check_len; i++) {
    const uint8_t ch = static_cast<uint8_t>(this->stoen_decrypted_[i]);
    if ((ch >= 0x20 && ch < 0x7F) || ch == '\r' || ch == '\n' || ch == '\t') {
      printable++;
    }
  }
  if (check_len > 0 && printable * 10 < check_len * 9) { // <90% printable
    ESP_LOGW(TAG,
             "Decrypted payload is not readable text - the decryption_key or "
             "system_title (IV) is wrong.");
  } else {
    ESP_LOGD(TAG, "STOEN decryption OK: %zu plaintext bytes.", ciphertext_len);
  }
  return true;
}

} // namespace dsmr_custom
} // namespace esphome

#endif // defined(USE_ARDUINO) || defined(USE_ESP_IDF)
