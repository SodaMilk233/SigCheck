#ifndef BINDER_H
#define BINDER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int get_binder_driver_fd(void);
int get_binder_service_handle(int fd, const char* service_name, uint32_t* handle);
int binder_transact(int fd, uint32_t handle, uint32_t code, const void* payload, size_t payload_size, const void** reply_data, size_t* reply_size, const void** reply_offsets, size_t* reply_offsets_size);
int free_binder_buffer(int fd, const void* buffer);

#ifdef __cplusplus
}
#endif

#endif
