#include <fcntl.h>
#include <mntent.h>
#include <sys/mount.h>

#include "daemon.hpp"
#include "logging.hpp"
#include "zygisk.hpp"

using namespace std::string_view_literals;

namespace {
void lazy_unmount(std::vector<std::string>& targets) {
    for (auto& target : targets) {
        auto mountpoint = target.data();
        if (umount2(mountpoint, MNT_DETACH) != -1) {
            LOGD("Unmounted (%s)", mountpoint);
        } else {
#ifndef NDEBUG
            PLOGE("Unmount (%s)", mountpoint);
#endif
        }
    }
}

bool is_root(mount_info info) {
    // Always keep mount points from modules
    if (info.root.starts_with("/adb/modules") || info.target.starts_with("/data/adb/modules")) {
        return false;
    }

    if (info.target.starts_with("/debug_ramdisk")) {
        return true;
    }

    // Unmount /system/bin directory for Magisk
    if (info.source == "magisk" && info.target.starts_with("/system/bin")) {
        return true;
    }

    return false;
}
}  // namespace

void unmount_root(std::vector<mount_info>& mount_infos, bool dry_run) {
    // We should filter the mount_infos before unmounting if the root directory presents
    if (mount_infos[0].target == "/") {
        mount_infos.erase(std::remove_if(mount_infos.begin(), mount_infos.end(),
                                         [](auto& info) { return !is_root(info); }),
                          mount_infos.end());
        std::reverse(mount_infos.begin(), mount_infos.end());
    }

    // Check again that we won't unmount the root directory
    if (!dry_run && mount_infos[0].target != "/") {
        // Do unmount
        std::vector<std::string> targets = {};
        for (auto& info : mount_infos) {
            targets.emplace_back(info.target);
        }
        lazy_unmount(targets);
    }
}

bool clean_mnt_ns(pid_t pid) {
    if (pid < 0) {
        LOGD("clean mount namespace with an invalid pid %d", pid);
        return false;
    }

    std::string ns_path = zygiskd::GetCleanMountNamespace(pid);
    if (!ns_path.starts_with("/proc/")) {
        LOGD("unable to get a clean mount namespace");
        return false;
    }

    auto clean_ns = open(ns_path.data(), O_RDONLY);
    if (clean_ns >= 0) {
        LOGD("set to clean mount ns [%s] fd=[%d]\n", ns_path.data(), clean_ns);
        setns(clean_ns, CLONE_NEWNS);
    } else {
        PLOGE("open ns [%s]", ns_path.data());
    }
    close(clean_ns);
    return true;
}
