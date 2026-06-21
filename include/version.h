// version.h
// app version: single source of truth for packing and display

#ifndef VERSION_H
#define VERSION_H

#include <stdint.h>
#include <stddef.h>

// packed as major*10000 + minor*100 + patch, so minor and patch each hold 0..99.
// monotonic, so the ota check (manifest.version > CURRENT_APP_VERSION) still orders by release.
extern const uint32_t CURRENT_APP_VERSION;

// constexpr so the constant initializes at compile time, no static-init ordering risk.
constexpr uint32_t app_version(uint32_t major, uint32_t minor, uint32_t patch) {
    return major * 10000u + minor * 100u + patch;
}
constexpr uint32_t app_version_major(uint32_t v) { return v / 10000u; }
constexpr uint32_t app_version_minor(uint32_t v) { return (v / 100u) % 100u; }
constexpr uint32_t app_version_patch(uint32_t v) { return v % 100u; }

// writes "vMAJOR.MINOR.PATCH" into out
void format_app_version(uint32_t v, char* out, size_t n);

#endif
