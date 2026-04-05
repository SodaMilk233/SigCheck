#include <string.h>
#include <stdio.h>
#include "proxy_check.h"
#include "utils/strutil.h"
#include "utils/memutil.h"

static void safe_strcpy(char* dest, const char* src, size_t dest_size) {
    if (dest_size == 0) return;
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
}

static int is_dynamic_proxy_class(const char* class_name) {
    return (my_strncmp(class_name, "$Proxy", 6) == 0);
}

static int get_class_name(JNIEnv* env, jobject obj, char* buf, size_t buf_size) {
    if (!env || !obj) return -1;
    jclass cls = (*env)->GetObjectClass(env, obj);
    if (!cls) { (*env)->ExceptionClear(env); return -1; }
    jclass class_cls = (*env)->GetObjectClass(env, cls);
    if (!class_cls) { (*env)->ExceptionClear(env); (*env)->DeleteLocalRef(env, cls); return -1; }
    jmethodID get_name = (*env)->GetMethodID(env, class_cls, "getName", "()Ljava/lang/String;");
    int ret = -1;
    if (get_name) {
        jstring str = (jstring)(*env)->CallObjectMethod(env, cls, get_name);
        if (str) {
            const char* cstr = (*env)->GetStringUTFChars(env, str, NULL);
            if (cstr) {
                safe_strcpy(buf, cstr, buf_size);
                ret = 0;
                (*env)->ReleaseStringUTFChars(env, str, cstr);
            }
            (*env)->DeleteLocalRef(env, str);
        }
    }
    (*env)->DeleteLocalRef(env, class_cls);
    (*env)->DeleteLocalRef(env, cls);
    return ret;
}

void check_field_proxy(JNIEnv* env, jobject context, field_proxy_result_t* result) {
    if (!env || !context || !result) return;
    memory_set(result, 0, sizeof(field_proxy_result_t));
    {
        jclass libcore = (*env)->FindClass(env, "libcore/io/Libcore");
        if (libcore) {
            jfieldID fid = (*env)->GetStaticFieldID(env, libcore, "os", "Llibcore/io/Os;");
            if (fid) {
                jobject os = (*env)->GetStaticObjectField(env, libcore, fid);
                if (os) {
                    int rc = get_class_name(env, os, result->os_class_name, sizeof(result->os_class_name));
                    if (rc == 0) {
                        result->os_is_proxy = is_dynamic_proxy_class(result->os_class_name);
                    }
                    (*env)->DeleteLocalRef(env, os);
                }
            }
            (*env)->DeleteLocalRef(env, libcore);
        }
    }
    {
        jclass ctx = (*env)->FindClass(env, "android/content/Context");
        if (ctx) {
            jmethodID get_pm = (*env)->GetMethodID(env, ctx, "getPackageManager", "()Landroid/content/pm/PackageManager;");
            if (get_pm) {
                jobject pm = (*env)->CallObjectMethod(env, context, get_pm);
                if (pm) {
                    jclass apm = (*env)->FindClass(env, "android/app/ApplicationPackageManager");
                    if (apm) {
                        jfieldID fid = (*env)->GetFieldID(env, apm, "mPM", "Landroid/content/pm/IPackageManager;");
                        if (fid) {
                            jobject ipm = (*env)->GetObjectField(env, pm, fid);
                            if (ipm) {
                                int rc = get_class_name(env, ipm, result->pm_class_name, sizeof(result->pm_class_name));
                                if (rc == 0) {
                                    result->pm_is_proxy = is_dynamic_proxy_class(result->pm_class_name);
                                }
                                (*env)->DeleteLocalRef(env, ipm);
                            }
                        }
                        (*env)->DeleteLocalRef(env, apm);
                    }
                    (*env)->DeleteLocalRef(env, pm);
                }
            }
            (*env)->DeleteLocalRef(env, ctx);
        }
    }
}

int check_parcel_creator(JNIEnv* env, char* info_buf, size_t buf_len) {
    if (info_buf && buf_len > 0) info_buf[0] = '\0';
    int result = 0;
    jclass pkg_info_cls = (*env)->FindClass(env, "android/content/pm/PackageInfo");
    if (!pkg_info_cls) return 0;
    jfieldID fid = (*env)->GetStaticFieldID(env, pkg_info_cls, "CREATOR", "Landroid/os/Parcelable$Creator;");
    if (!fid) {
        (*env)->DeleteLocalRef(env, pkg_info_cls);
        return 0;
    }
    jobject creator = (*env)->GetStaticObjectField(env, pkg_info_cls, fid);
    if (!creator) {
        (*env)->DeleteLocalRef(env, pkg_info_cls);
        return 0;
    }
    jclass creator_cls = (*env)->GetObjectClass(env, creator);
    if (!creator_cls) {
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, pkg_info_cls);
        (*env)->DeleteLocalRef(env, creator);
        return 0;
    }
    jclass class_cls = (*env)->FindClass(env, "java/lang/Class");
    if (class_cls) {
        jmethodID get_name = (*env)->GetMethodID(env, class_cls, "getName", "()Ljava/lang/String;");
        if (get_name) {
            jstring jname = (jstring)(*env)->CallObjectMethod(env, creator_cls, get_name);
            if (jname) {
                const char* name = (*env)->GetStringUTFChars(env, jname, NULL);
                if (name && my_strstr(name, "android.content.pm.PackageInfo$1") == NULL) {
                    if (info_buf && buf_len > 0) snprintf(info_buf, buf_len, "%s", name);
                    result = 1;
                }
                if (name) (*env)->ReleaseStringUTFChars(env, jname, name);
                (*env)->DeleteLocalRef(env, jname);
            }
            if (!result) {
                jmethodID get_cl = (*env)->GetMethodID(env, class_cls, "getClassLoader", "()Ljava/lang/ClassLoader;");
                if (get_cl) {
                    jobject cl = (*env)->CallObjectMethod(env, creator_cls, get_cl);
                    if (cl) {
                        jclass cl_cls = (*env)->GetObjectClass(env, cl);
                        if (cl_cls) {
                            jstring jcl_name = (jstring)(*env)->CallObjectMethod(env, cl_cls, get_name);
                            if (jcl_name) {
                                const char* cl_name = (*env)->GetStringUTFChars(env, jcl_name, NULL);
                                if (cl_name && my_strstr(cl_name, "java.lang.BootClassLoader") == NULL) {
                                    if (info_buf && buf_len > 0) snprintf(info_buf, buf_len, "%s", cl_name);
                                    result = 1;
                                }
                                if (cl_name) (*env)->ReleaseStringUTFChars(env, jcl_name, cl_name);
                                (*env)->DeleteLocalRef(env, jcl_name);
                            }
                            (*env)->DeleteLocalRef(env, cl_cls);
                        }
                        (*env)->DeleteLocalRef(env, cl);
                    }
                }
            }
        }
        (*env)->DeleteLocalRef(env, class_cls);
    } else { (*env)->ExceptionClear(env); }
    (*env)->DeleteLocalRef(env, creator_cls);
    (*env)->DeleteLocalRef(env, creator);
    (*env)->DeleteLocalRef(env, pkg_info_cls);
    return result;
}