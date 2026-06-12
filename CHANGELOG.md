# Changelog

All notable changes to this project will be documented in this file.

## [1.3.0] - 2026-06-12

### Added
- **`method: Poland_STOEN`:** Support for the Polish Elgama GAMA 350 meter
  (Stoen Operator), ported from the BAJO_STOEN branch by @BJozwiak.
  - Telegram envelope `/EGM5G35\r\n\r\n` + BER length prefix + AES-128-GCM
    encrypted DLMS payload + `!XXXX\r\n` footer (~583 bytes total).
  - Works on ESP8266 (Arduino framework, rweather/Crypto) and on ESP-IDF
    (hardware-accelerated MbedTLS) via `USE_ARDUINO`/`USE_ESP_IDF` guards.
  - Internal receive buffers are sized from the existing
    `max_telegram_length` option, so one YAML knob governs the whole
    pipeline; `max_telegram_length: 1024` and uart `rx_buffer_size: 1024`
    are ample.
  - In this mode `receive_timeout` is the idle gap that marks the end of a
    telegram and must stay below the meter's ~1 s send interval. Values
    above 500 ms log a setup warning, since telegrams would accumulate and
    overflow the receive buffer.
  - Requires `decryption_key` (validated at config time).
  - Optional `system_title` (16 hex chars) overrides the 8-byte IV prefix
    for meters that use their real system title internally while
    transmitting an empty one; `scripts/try_decrypt.py` finds the right
    value offline from one captured telegram.
  - Logs a warning when the decrypted payload is not readable text (wrong
    `decryption_key` or `system_title`), instead of silently publishing
    binary garbage.
  - New compile-test config: `test-configs/test-arduino-esp8266-stoen.yaml`.

### Changed
- Removed the ESP-IDF-only UDP debug sockets (`sys/socket.h`, `netdb.h`) that
  the reference implementation used; multi-byte telegram fields are assembled
  manually, so no lwIP/`ntohl` dependencies remain.
- Fixed an off-by-one from the reference implementation that skipped one body
  byte when a false footer (`!` followed by CR but no LF) appeared inside the
  encrypted payload.

### Breaking Changes
None - `method` defaults to `plain` and existing plain/encrypted
configurations behave exactly as before.

## [1.2.0] - 2025-12-03

### Added
- **ESP-IDF Encryption Support:** Added experimental support for AES-GCM decryption on ESP-IDF platforms (e.g., ESP32-C6).
  - Uses system MbedTLS library with hardware acceleration where available.
  - Implemented via PlatformIO `extra_scripts` to handle library linking.

## [1.1.0] - 2025-12-02

### Added
- ESP-IDF framework support for ESP32-C6, ESP32-H2, and future chips
- Framework-agnostic string handling using conditional compilation
- AUTO_LOAD directive for sensor/text_sensor components (fixes #7)
- Comprehensive testing configuration files
- GitHub Actions CI/CD for compile testing

### Changed
- Replaced hardcoded Arduino.h dependency with conditional compilation
- Migrated Arduino String operations to framework-agnostic implementation
- Updated util.h to support both Arduino String and std::string

### Fixed
- Issue #6: Arduino.h missing file error when using ESP-IDF framework
- Issue #7: sensor.h missing when no sensor platform defined in YAML configuration

### Breaking Changes
None - fully backward compatible with existing configurations.

## [1.0.2] - Previous Release
- Initial stable release with custom OBIS sensor support
