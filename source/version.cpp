// version.cpp
// app version constant and display formatting

#include "version.h"
#include <cstdio>

// v2.5.0 - encoding lives in version.h.
const uint32_t CURRENT_APP_VERSION = 20500;

void format_app_version(uint32_t v, char* out, size_t n) {
    std::snprintf(out, n, "v%lu.%lu.%lu",
        (unsigned long)app_version_major(v),
        (unsigned long)app_version_minor(v),
        (unsigned long)app_version_patch(v));
}
