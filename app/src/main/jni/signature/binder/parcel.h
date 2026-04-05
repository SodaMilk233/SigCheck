#ifndef PARCEL_H
#define PARCEL_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t* buf;
    size_t size;
    size_t cap;
} ParcelBuilder;

void parcel_init(ParcelBuilder* pb);
void parcel_free(ParcelBuilder* pb);
void parcel_writeInt32(ParcelBuilder* pb, int32_t x);
void parcel_writeInt64(ParcelBuilder* pb, int64_t x);
void parcel_writeString16(ParcelBuilder* pb, const char* s);
void parcel_writeInterfaceToken(ParcelBuilder* pb, const char* interface_name);
void parcel_writeVersionedPackage(ParcelBuilder* pb, const char* packageName, int32_t versionCode);

#endif