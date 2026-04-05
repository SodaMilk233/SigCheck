#include <jni.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <asm/unistd.h>
#include "syscall.h"
#include "utils/strutil.h"
#include "sandbox_check.h"

static int check_dir_path(JNIEnv* env) {
    int result = 0;
    jclass activity_thread_class = (*env)->FindClass(env, "android/app/ActivityThread");
    if (!activity_thread_class) return 0;
    jmethodID current_pkg = (*env)->GetStaticMethodID(env, activity_thread_class, "currentPackageName", "()Ljava/lang/String;");
    if (!current_pkg) return 0;
    jstring pkg_str = (jstring)(*env)->CallStaticObjectMethod(env, activity_thread_class, current_pkg);
    if (!pkg_str) return 0;
    const char* package_name = (*env)->GetStringUTFChars(env, pkg_str, NULL);
    if (!package_name) {
        (*env)->DeleteLocalRef(env, pkg_str);
        return 0;
    }
    char mark_path[256], real_path[256], link_path[64];
    snprintf(mark_path, sizeof(mark_path), "/data/data/%s/mark", package_name);
    long fd = syscall_invoke(__NR_openat, AT_FDCWD, (long)mark_path, 0102, 0644, 0, 0);
    if (fd >= 0) {
        snprintf(link_path, sizeof(link_path), "/proc/self/fd/%ld", fd);
        long len = syscall_invoke(__NR_readlinkat, AT_FDCWD, (long)link_path, (long)real_path, sizeof(real_path) - 1, 0, 0);
        syscall_invoke(__NR_close, fd, 0, 0, 0, 0, 0);
        syscall_invoke(__NR_unlinkat, AT_FDCWD, (long)mark_path, 0, 0, 0, 0);

        if (len > 0) {
            real_path[len] = '\0';
            if (my_strcmp(real_path, mark_path) != 0) {
                result = 1;
            }
        }
    }
    if (!result) {
        jmethodID current_thread = (*env)->GetStaticMethodID(env, activity_thread_class, "currentActivityThread", "()Landroid/app/ActivityThread;");
        if (current_thread) {
            jobject thread_obj = (*env)->CallStaticObjectMethod(env, activity_thread_class, current_thread);
            if (thread_obj) {
                jmethodID get_app = (*env)->GetMethodID(env, (*env)->GetObjectClass(env, thread_obj), "getApplication", "()Landroid/app/Application;");
                if (get_app) {
                    jobject app = (*env)->CallObjectMethod(env, thread_obj, get_app);
                    if (app) {
                        jclass app_cls = (*env)->GetObjectClass(env, app);
                        jmethodID get_info = (*env)->GetMethodID(env, app_cls, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
                        if (get_info) {
                            jobject info = (*env)->CallObjectMethod(env, app, get_info);
                            if (info) {
                                jclass info_cls = (*env)->GetObjectClass(env, info);
                                jfieldID data_dir_id = (*env)->GetFieldID(env, info_cls, "dataDir", "Ljava/lang/String;");
                                if (data_dir_id) {
                                    jstring data_dir_str = (jstring)(*env)->GetObjectField(env, info, data_dir_id);
                                    if (data_dir_str) {
                                        const char* data_dir = (*env)->GetStringUTFChars(env, data_dir_str, NULL);
                                        if (data_dir) {
                                            char normal1[256], normal2[256];
                                            snprintf(normal1, sizeof(normal1), "/data/user/0/%s", package_name);
                                            snprintf(normal2, sizeof(normal2), "/data/data/%s", package_name);

                                            if (my_strcmp(data_dir, normal1) != 0 && my_strcmp(data_dir, normal2) != 0) {
                                                result = 1;
                                            } else {
                                                char parent_path[256];
                                                snprintf(parent_path, sizeof(parent_path), "%s/..", data_dir);
                                                if (syscall_invoke(__NR_faccessat, AT_FDCWD, (long)parent_path, R_OK, 0, 0, 0) == 0) {
                                                    result = 1;
                                                }
                                            }
                                            (*env)->ReleaseStringUTFChars(env, data_dir_str, data_dir);
                                        }
                                        (*env)->DeleteLocalRef(env, data_dir_str);
                                    }
                                }
                                (*env)->DeleteLocalRef(env, info_cls);
                                (*env)->DeleteLocalRef(env, info);
                            }
                        }
                        (*env)->DeleteLocalRef(env, app_cls);
                        (*env)->DeleteLocalRef(env, app);
                    }
                }
                (*env)->DeleteLocalRef(env, thread_obj);
            }
        }
    }
    (*env)->ReleaseStringUTFChars(env, pkg_str, package_name);
    (*env)->DeleteLocalRef(env, pkg_str);
    (*env)->DeleteLocalRef(env, activity_thread_class);
    return result;
}

static int check_injected_libs(void) {
    static const char* injected_libs[] = {
        "libpine.so",
        "libchaos.so",
        "liblsplant.so",
        "libioredirect.so",
        "libdocker-jni-1.5.so",
        NULL
    };
    long fd = syscall_invoke(__NR_openat, AT_FDCWD, (long)"/proc/self/maps", O_RDONLY, 0, 0, 0);
    if (fd < 0) return 0;
    char buf[1024];
    long bytes;
    int found = 0;
    while ((bytes = syscall_invoke(__NR_read, fd, (long)buf, sizeof(buf) - 1, 0, 0, 0)) > 0) {
        buf[bytes] = '\0';
        for (int i = 0; injected_libs[i] != NULL; i++) {
            if (my_strstr(buf, injected_libs[i]) != NULL) {
                found = 1;
                goto end;
            }
        }
    }
end:
    syscall_invoke(__NR_close, fd, 0, 0, 0, 0, 0);
    return found;
}

static int check_service_count(JNIEnv* env) {
    jclass cls = (*env)->FindClass(env, "android/os/ServiceManager");
    if (!cls) return 0;
    jfieldID fid = (*env)->GetStaticFieldID(env, cls, "sCache", "Ljava/util/Map;");
    if (!fid) {
        (*env)->DeleteLocalRef(env, cls);
        return 0;
    }
    jobject map = (*env)->GetStaticObjectField(env, cls, fid);
    int count = 0;
    if (map) {
        jclass mapCls = (*env)->GetObjectClass(env, map);
        if (mapCls) {
            jmethodID size = (*env)->GetMethodID(env, mapCls, "size", "()I");
            if (size) {
                count = (*env)->CallIntMethod(env, map, size);
            }
            (*env)->DeleteLocalRef(env, mapCls);
        }
        (*env)->DeleteLocalRef(env, map);
    }
    (*env)->DeleteLocalRef(env, cls);
    return count;
}

int check_sandbox(JNIEnv* env) {
    int r1 = check_dir_path(env);
    int r2 = check_injected_libs();
    int svc_count = check_service_count(env);
    int result = (r1 || r2 || svc_count > 50) ? 1 : 0;
    return result;
}
