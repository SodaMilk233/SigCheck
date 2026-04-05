#include "parcel.h"
#include "utils/memutil.h"
#include "utils/sysutil.h"
#include <stdint.h>

#define PARCEL_MAX_ALLOC (64 * 1024 * 1024)

void parcel_init(ParcelBuilder* pb) {
    if (pb) {
        pb->buf = NULL;
        pb->size = 0;
        pb->cap = 0;
    }
}

void parcel_free(ParcelBuilder* pb) {
    if (pb && pb->buf) {
        memory_free(pb->buf, pb->cap);
        pb->buf = NULL;
        pb->size = 0;
        pb->cap = 0;
    }
}

static int parcel_ensure(ParcelBuilder* pb, size_t more) {
    if (!pb) return -1;
    if (pb->size + more <= pb->cap) return 0;
    size_t ncap = pb->cap ? pb->cap : 256;
    while (pb->size + more > ncap) {
        if (ncap > (SIZE_MAX / 2)) return -1;
        ncap *= 2;
    }
    if (ncap > PARCEL_MAX_ALLOC) return -1;
    uint8_t* nb = (uint8_t*)memory_alloc(ncap);
    if (!nb) return -1;
    if (pb->buf && pb->size) {
        memory_copy(nb, pb->buf, pb->size);
        memory_free(pb->buf, pb->cap);
    }
    pb->buf = nb;
    pb->cap = ncap;
    return 0;
}

void parcel_writeInt32(ParcelBuilder* pb, int32_t x) {
    if (parcel_ensure(pb, 4) == 0) {
        memory_copy(pb->buf + pb->size, &x, 4);
        pb->size += 4;
    }
}

void parcel_writeInt64(ParcelBuilder* pb, int64_t x) {
    if (parcel_ensure(pb, 8) == 0) {
        memory_copy(pb->buf + pb->size, &x, 8);
        pb->size += 8;
    }
}

static void parcel_align(ParcelBuilder* pb) {
    size_t pad = (-pb->size) & 3U;
    if (pad) {
        if (parcel_ensure(pb, pad) == 0) {
            memory_set(pb->buf + pb->size, 0, pad);
            pb->size += pad;
        }
    }
}

void parcel_writeString16(ParcelBuilder* pb, const char* s) {
    if (!s) {
        parcel_writeInt32(pb, -1);
        return;
    }
    int32_t n = 0;
    while (s[n] != '\0') ++n;
    if (n > 0x7FFFFFFF) n = 0x7FFFFFFF;
    parcel_writeInt32(pb, n);
    size_t need = 2 * (size_t)(n + 1) + 4;
    if (need < (size_t)n) return;
    if (parcel_ensure(pb, need) == 0) {
        for (int i = 0; i < n; ++i) {
            uint16_t ch = (uint16_t)(uint8_t)s[i];
            memory_copy(pb->buf + pb->size, &ch, 2);
            pb->size += 2;
        }
        uint16_t zero = 0;
        memory_copy(pb->buf + pb->size, &zero, 2);
        pb->size += 2;
        parcel_align(pb);
    }
}

void parcel_writeInterfaceToken(ParcelBuilder* pb, const char* interface_name) {
    int sdk = android_get_version();
    const uint32_t STRICT_MODE_PENALTY_GATHER = (sdk >= 29) ? 0x80000000u : 0x00400000u;
    parcel_writeInt32(pb, (int32_t)STRICT_MODE_PENALTY_GATHER);
    if (sdk >= 30) {
        parcel_writeInt32(pb, -1);
        parcel_writeInt32(pb, 0x53595354);
    } else if (sdk == 29) {
        parcel_writeInt32(pb, -1);
    }
    parcel_writeString16(pb, interface_name);
}

void parcel_writeVersionedPackage(ParcelBuilder* pb, const char* packageName, int32_t versionCode) {
    parcel_writeString16(pb, packageName);
    parcel_writeInt32(pb, versionCode);
}