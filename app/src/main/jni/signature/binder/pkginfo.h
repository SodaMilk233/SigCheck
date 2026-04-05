#ifndef PKGINFO_H
#define PKGINFO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

unsigned char* get_signature_from_binder(size_t* len);

#ifdef __cplusplus
}
#endif

#endif
