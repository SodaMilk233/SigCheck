#ifndef SYSCALL_H
#define SYSCALL_H

#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

long syscall_invoke(long number, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6);

#ifdef __cplusplus
}
#endif

#endif
