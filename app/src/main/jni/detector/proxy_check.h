#ifndef PROXY_CHECK_H
#define PROXY_CHECK_H

#include <jni.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int os_is_proxy;
    int pm_is_proxy;
    char os_class_name[256];
    char pm_class_name[256];
} field_proxy_result_t;

void check_field_proxy(JNIEnv* env, jobject context, field_proxy_result_t* result);
int check_parcel_creator(JNIEnv* env, char* info_buf, size_t buf_len);

#ifdef __cplusplus
}
#endif
#endif