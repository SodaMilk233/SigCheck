#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include "signature/binder/pkginfo.h"
#include "signature/crypto/sha256.h"
#include "utils/memutil.h"
#include "utils/strutil.h"
#include "utils/sysutil.h"
#include "detector/proxy_check.h"
#include "detector/library_check.h"
#include "detector/sandbox_check.h"
#include "detector/lsposed_check.h"
#include "detector/seccomp_check.h"
#include "detector/riskmem_check.h"


jobject createTextView(JNIEnv* env, jobject context, const char* text, float textSize, int color, int gravity, int paddingBottom, int isBold) {
    jclass textViewClass = (*env)->FindClass(env, "android/widget/TextView");
    if (!textViewClass) return NULL;
    jmethodID ctor = (*env)->GetMethodID(env, textViewClass, "<init>", "(Landroid/content/Context;)V");
    if (!ctor) {
        (*env)->DeleteLocalRef(env, textViewClass);
        return NULL;
    }
    jobject textView = (*env)->NewObject(env, textViewClass, ctor, context);
    if (!textView) {
        (*env)->DeleteLocalRef(env, textViewClass);
        return NULL;
    }
    jclass tvClass = (*env)->GetObjectClass(env, textView);
    if (!tvClass) {
        (*env)->DeleteLocalRef(env, textView);
        (*env)->DeleteLocalRef(env, textViewClass);
        return NULL;
    }
    if (text) {
        jmethodID setText = (*env)->GetMethodID(env, tvClass, "setText", "(Ljava/lang/CharSequence;)V");
        if (setText) {
            jstring jtext = (*env)->NewStringUTF(env, text);
            (*env)->CallVoidMethod(env, textView, setText, jtext);
            (*env)->DeleteLocalRef(env, jtext);
        }
    }
    jmethodID setTextSize = (*env)->GetMethodID(env, tvClass, "setTextSize", "(F)V");
    if (setTextSize) (*env)->CallVoidMethod(env, textView, setTextSize, textSize);
    jmethodID setTextColor = (*env)->GetMethodID(env, tvClass, "setTextColor", "(I)V");
    if (setTextColor) (*env)->CallVoidMethod(env, textView, setTextColor, color);
    jmethodID setGravity = (*env)->GetMethodID(env, tvClass, "setGravity", "(I)V");
    if (setGravity) (*env)->CallVoidMethod(env, textView, setGravity, gravity);
    jmethodID setPadding = (*env)->GetMethodID(env, tvClass, "setPadding", "(IIII)V");
    if (setPadding) (*env)->CallVoidMethod(env, textView, setPadding, 0, 0, 0, paddingBottom);
    if (isBold) {
        jmethodID setTypeface = (*env)->GetMethodID(env, tvClass, "setTypeface", "(Landroid/graphics/Typeface;)V");
        jclass typefaceClass = (*env)->FindClass(env, "android/graphics/Typeface");
        if (typefaceClass && setTypeface) {
            jfieldID boldField = (*env)->GetStaticFieldID(env, typefaceClass, "DEFAULT_BOLD", "Landroid/graphics/Typeface;");
            if (boldField) {
                jobject boldTypeface = (*env)->GetStaticObjectField(env, typefaceClass, boldField);
                (*env)->CallVoidMethod(env, textView, setTypeface, boldTypeface);
            }
        }
        if (typefaceClass) (*env)->DeleteLocalRef(env, typefaceClass);
    }
    (*env)->DeleteLocalRef(env, tvClass);
    (*env)->DeleteLocalRef(env, textViewClass);
    return textView;
}

void addView(JNIEnv* env, jobject parent, jobject child) {
    if (!child) return;
    jclass parentClass = (*env)->GetObjectClass(env, parent);
    if (!parentClass) return;
    jmethodID addView = (*env)->GetMethodID(env, parentClass, "addView", "(Landroid/view/View;)V");
    if (addView) (*env)->CallVoidMethod(env, parent, addView, child);
    (*env)->DeleteLocalRef(env, parentClass);
}

void hexStringToBytes(const char* hex, unsigned char* bytes, int len) {
    for (int i = 0; i < len; i++) {
        sscanf(&hex[i * 2], "%2hhx", &bytes[i]);
    }
}

void bytesToHexString(const unsigned char* bytes, int len, char* hex) {
    for (int i = 0; i < len; i++) {
        sprintf(&hex[i * 2], "%02X", bytes[i]);
    }
    hex[len * 2] = '\0';
}

JNIEXPORT void JNICALL NativeOnCreate(JNIEnv* env, jobject thiz, jobject savedInstanceState) {
    jclass activityClass = (*env)->GetObjectClass(env, thiz);
    jclass superClass = (*env)->GetSuperclass(env, activityClass);
    jmethodID superOnCreate = (*env)->GetMethodID(env, superClass, "onCreate", "(Landroid/os/Bundle;)V");
    if (superOnCreate) (*env)->CallNonvirtualVoidMethod(env, thiz, superClass, superOnCreate, savedInstanceState);
    (*env)->DeleteLocalRef(env, superClass);
    jmethodID getWindow = (*env)->GetMethodID(env, activityClass, "getWindow", "()Landroid/view/Window;");
    jobject window = getWindow ? (*env)->CallObjectMethod(env, thiz, getWindow) : NULL;
    if (window) {
        jclass windowClass = (*env)->FindClass(env, "android/view/Window");
        if (windowClass) {
            jmethodID setStatusBarColor = (*env)->GetMethodID(env, windowClass, "setStatusBarColor", "(I)V");
            jmethodID setNavigationBarColor = (*env)->GetMethodID(env, windowClass, "setNavigationBarColor", "(I)V");
            if (setStatusBarColor) (*env)->CallVoidMethod(env, window, setStatusBarColor, 0xFF1A1A2E);
            if (setNavigationBarColor) (*env)->CallVoidMethod(env, window, setNavigationBarColor, 0xFF1A1A2E);
            (*env)->DeleteLocalRef(env, windowClass);
        }
        (*env)->DeleteLocalRef(env, window);
    }
    jclass linearLayoutClass = (*env)->FindClass(env, "android/widget/LinearLayout");
    jmethodID llCtor = (*env)->GetMethodID(env, linearLayoutClass, "<init>", "(Landroid/content/Context;)V");
    jobject rootLayout = (*env)->NewObject(env, linearLayoutClass, llCtor, thiz);
    if (rootLayout) {
        jclass llClass = (*env)->GetObjectClass(env, rootLayout);
        jmethodID setOrientation = (*env)->GetMethodID(env, llClass, "setOrientation", "(I)V");
        jmethodID setGravity = (*env)->GetMethodID(env, llClass, "setGravity", "(I)V");
        jmethodID setPadding = (*env)->GetMethodID(env, llClass, "setPadding", "(IIII)V");
        if (setOrientation) (*env)->CallVoidMethod(env, rootLayout, setOrientation, 1);
        if (setGravity) (*env)->CallVoidMethod(env, rootLayout, setGravity, 17);
        if (setPadding) (*env)->CallVoidMethod(env, rootLayout, setPadding, 40, 48, 40, 48);
        jclass viewClass = (*env)->FindClass(env, "android/view/View");
        if (viewClass) {
            jmethodID setBackgroundColor = (*env)->GetMethodID(env, viewClass, "setBackgroundColor", "(I)V");
            if (setBackgroundColor) (*env)->CallVoidMethod(env, rootLayout, setBackgroundColor, 0xFF1A1A2E);
            (*env)->DeleteLocalRef(env, viewClass);
        }
        char app_sha256[] = "F0E136EA763DAC81460EE5056801A386FBD9AF0B7421048B284B585F4F54AFD9";
        unsigned char expected[32];
        hexStringToBytes(app_sha256, expected, 32);
        field_proxy_result_t proxy_result;
        memset(&proxy_result, 0, sizeof(proxy_result));
        check_field_proxy(env, thiz, &proxy_result);
        int proxy_detected = (proxy_result.os_is_proxy || proxy_result.pm_is_proxy);
        int libc_tampered = check_library_integrity("libc.so");
        int libart_tampered = check_library_integrity("libart.so");
        int sandbox_detected = check_sandbox(env);
        char creator_info[128] = {0};
        int creator_detected = check_parcel_creator(env, creator_info, sizeof(creator_info));
        int lsposed_hooked = check_lsposed_hook(env);
        int seccomp_filter_detected = check_seccomp_filter();
        char suspicious_mem_info[512] = {0};
        const char* suspicious_mem_detected = check_suspicious_maps(suspicious_mem_info, sizeof(suspicious_mem_info));
        int any_threat_detected = (proxy_detected || libc_tampered == 1 || libart_tampered == 1 || sandbox_detected || creator_detected || lsposed_hooked || seccomp_filter_detected < 0 || suspicious_mem_detected);
        unsigned char* cert = NULL;
        size_t cert_len = 0;
        char actual_hash_str[65] = "N/A";
        int match = 0;
        if (!any_threat_detected) {
            cert = get_signature_from_binder(&cert_len);
            if (cert && cert_len > 0) {
                unsigned char hash[32];
                sha256(cert, cert_len, hash);
                bytesToHexString(hash, 32, actual_hash_str);
                match = (my_memcmp(hash, expected, 32) == 0);
                memory_free(cert, cert_len);
            }
        }
        int sdk_ver = android_get_version();
        char sdk_value[16];
        snprintf(sdk_value, sizeof(sdk_value), "API %d", sdk_ver);
        char title_text[512];
        char status_text[256];
        int status_color;
        if (any_threat_detected) {
            snprintf(title_text, sizeof(title_text), "⚠ 签名验证不可信");
            snprintf(status_text, sizeof(status_text), "检测到异常，签名验证结果不可信！");
            status_color = 0xFFFF5252;
            char threat_details[1024] = {0};
            int offset = 0;
            if (proxy_result.os_is_proxy)
                offset += snprintf(threat_details + offset, sizeof(threat_details) - offset, "• Os被代理: %s\n", proxy_result.os_class_name);
            if (proxy_result.pm_is_proxy)
                offset += snprintf(threat_details + offset, sizeof(threat_details) - offset, "• Pm被代理: %s\n", proxy_result.pm_class_name);
            if (creator_detected)
                offset += snprintf(threat_details + offset, sizeof(threat_details) - offset, "• Creator被篡改: %s\n", creator_info);
            if (libc_tampered == 1)
                offset += snprintf(threat_details + offset, sizeof(threat_details) - offset, "• libc.so被篡改\n");
            if (libart_tampered == 1)
                offset += snprintf(threat_details + offset, sizeof(threat_details) - offset, "• libart.so被篡改\n");
            if (lsposed_hooked)
                offset += snprintf(threat_details + offset, sizeof(threat_details) - offset, "• 检测到hook注入\n");
            if (sandbox_detected)
                offset += snprintf(threat_details + offset, sizeof(threat_details) - offset, "• 检测到多开/分身环境\n");
            if (seccomp_filter_detected < 0)
                offset += snprintf(threat_details + offset, sizeof(threat_details) - offset, "• 检测到seccomp过滤器劫持\n");
            if (suspicious_mem_detected)
                offset += snprintf(threat_details + offset, sizeof(threat_details) - offset, "• 检测到可疑内存:\n%s\n", suspicious_mem_detected);
            jobject titleView = createTextView(env, thiz, title_text, 24.0f, 0xFFFF5252, 17, 24, 1);
            jobject labelView1 = createTextView(env, thiz, "系统版本", 14.0f, 0xFFFF5252, 17, 8, 0);
            jobject valueView1 = createTextView(env, thiz, sdk_value, 14.0f, 0xFFFF5252, 17, 24, 0);
            jobject threatLabel = createTextView(env, thiz, "检测到的威胁:", 14.0f, 0xFFFF5252, 17, 8, 1);
            jobject threatDetailsView = createTextView(env, thiz, threat_details, 12.0f, 0xFFFF5252, 17, 24, 0);
            jobject statusLabel = createTextView(env, thiz, "验证状态", 14.0f, 0xFFFF5252, 17, 8, 0);
            jobject statusView = createTextView(env, thiz, status_text, 18.0f, status_color, 17, 16, 1);
            addView(env, rootLayout, titleView);
            addView(env, rootLayout, labelView1);
            addView(env, rootLayout, valueView1);
            addView(env, rootLayout, threatLabel);
            addView(env, rootLayout, threatDetailsView);
            addView(env, rootLayout, statusLabel);
            addView(env, rootLayout, statusView);
            if (titleView) (*env)->DeleteLocalRef(env, titleView);
            if (labelView1) (*env)->DeleteLocalRef(env, labelView1);
            if (valueView1) (*env)->DeleteLocalRef(env, valueView1);
            if (threatLabel) (*env)->DeleteLocalRef(env, threatLabel);
            if (threatDetailsView) (*env)->DeleteLocalRef(env, threatDetailsView);
            if (statusLabel) (*env)->DeleteLocalRef(env, statusLabel);
            if (statusView) (*env)->DeleteLocalRef(env, statusView);
        } else {
            snprintf(title_text, sizeof(title_text), "签名验证");
            snprintf(status_text, sizeof(status_text), match ? "验证成功" : "验证失败");
            status_color = match ? 0xFF4CAF50 : 0xFFFF5252;
            jobject titleView = createTextView(env, thiz, title_text, 24.0f, 0xFFFFFFFF, 17, 24, 1);
            jobject labelView1 = createTextView(env, thiz, "系统版本", 14.0f, 0xFFFFFFFF, 17, 8, 0);
            jobject valueView1 = createTextView(env, thiz, sdk_value, 14.0f, 0xFFA0A0A0, 17, 24, 0);
            jobject labelView2 = createTextView(env, thiz, "预期签名", 14.0f, 0xFFFFFFFF, 17, 8, 0);
            jobject expectedView = createTextView(env, thiz, app_sha256, 14.0f, 0xFFA0A0A0, 17, 24, 0);
            jobject labelView3 = createTextView(env, thiz, "实际签名", 14.0f, 0xFFFFFFFF, 17, 8, 0);
            jobject actualView = createTextView(env, thiz, actual_hash_str, 14.0f, match ? 0xFFA0A0A0 : 0xFFFF5252, 17, 24, 0);
            jobject statusLabel = createTextView(env, thiz, "验证状态", 14.0f, 0xFFFFFFFF, 17, 8, 0);
            jobject statusView = createTextView(env, thiz, status_text, 18.0f, status_color, 17, 16, 1);
            addView(env, rootLayout, titleView);
            addView(env, rootLayout, labelView1);
            addView(env, rootLayout, valueView1);
            addView(env, rootLayout, labelView2);
            addView(env, rootLayout, expectedView);
            addView(env, rootLayout, labelView3);
            addView(env, rootLayout, actualView);
            addView(env, rootLayout, statusLabel);
            addView(env, rootLayout, statusView);
            if (titleView) (*env)->DeleteLocalRef(env, titleView);
            if (labelView1) (*env)->DeleteLocalRef(env, labelView1);
            if (valueView1) (*env)->DeleteLocalRef(env, valueView1);
            if (labelView2) (*env)->DeleteLocalRef(env, labelView2);
            if (expectedView) (*env)->DeleteLocalRef(env, expectedView);
            if (labelView3) (*env)->DeleteLocalRef(env, labelView3);
            if (actualView) (*env)->DeleteLocalRef(env, actualView);
            if (statusLabel) (*env)->DeleteLocalRef(env, statusLabel);
            if (statusView) (*env)->DeleteLocalRef(env, statusView);
        }
        jmethodID setContentView = (*env)->GetMethodID(env, activityClass, "setContentView", "(Landroid/view/View;)V");
        if (setContentView) (*env)->CallVoidMethod(env, thiz, setContentView, rootLayout);
        (*env)->DeleteLocalRef(env, rootLayout);
    }
    (*env)->DeleteLocalRef(env, linearLayoutClass);
    (*env)->DeleteLocalRef(env, activityClass);
}



JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved __attribute__((unused))) {
    JNIEnv* env;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    jclass cls = (*env)->FindClass(env, "littlewhitebear/signverification/MainActivity");
    if (!cls) return JNI_ERR;
    JNINativeMethod methods[] = {
        {"onCreate", "(Landroid/os/Bundle;)V", (void*)NativeOnCreate}
    };
    if ((*env)->RegisterNatives(env, cls, methods, sizeof(methods)/sizeof(methods[0])) < 0) return JNI_ERR;
    return JNI_VERSION_1_6;
}
