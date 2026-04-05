#pragma once

#include <stddef.h>
#include <stdint.h>

void sha256(const void *data, size_t len, uint8_t *hash);