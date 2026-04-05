#include "sysutil.h"
#include <sys/system_properties.h>

static int cached_sdk_version = -1;

int android_get_version(void) {
    if (cached_sdk_version > 0) return cached_sdk_version;
    char value[92] = {0};
    int len = __system_property_get("ro.build.version.sdk", value);
    if (len <= 0) {
        cached_sdk_version = 0;
        return 0;
    }
    int version = 0;
    for (int i = 0; i < len && value[i] >= '0' && value[i] <= '9'; i++) {
        version = version * 10 + (value[i] - '0');
    }
    cached_sdk_version = version;
    return version;
}