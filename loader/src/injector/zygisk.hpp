#pragma once

#include <jni.h>

void hook_entry(void *self_handle);

void revert_unmount_ksu();

void revert_unmount_magisk();

void hookJniNativeMethods(JNIEnv *env, const char *clz, JNINativeMethod *methods, int numMethods);
