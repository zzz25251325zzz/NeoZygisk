#pragma once

#include <jni.h>

void hook_entry(void *start_addr, size_t block_size);

void revert_unmount_ksu();

void revert_unmount_magisk();

void hookJniNativeMethods(JNIEnv *env, const char *clz, JNINativeMethod *methods, int numMethods);
