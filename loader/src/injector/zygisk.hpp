#pragma once

#include <jni.h>
#include <sys/types.h>

#include "files.hpp"

void hook_entry(void *start_addr, size_t block_size);

bool clean_mnt_ns(pid_t pid);

void unmount_root(std::vector<mount_info> &mount_infos, bool dry_run);

void hookJniNativeMethods(JNIEnv *env, const char *clz, JNINativeMethod *methods, int numMethods);

void clean_trace(const char *path, size_t load, size_t unload, bool spoof_maps);
