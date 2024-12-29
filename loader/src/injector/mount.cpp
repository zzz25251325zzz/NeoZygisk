#include <fcntl.h>
#include <mntent.h>
#include <sys/mount.h>

#include "daemon.hpp"
#include "logging.hpp"
#include "zygisk.hpp"

using namespace std::string_view_literals;

namespace {
void magical_mount(mount_info info) {
    // TODO: not implemented yet, might be useful in some edge case
    LOGD("Should re-mount %s", info.target.data());
}

// Return true for mount points needed by applications which are not on the denylist
bool is_module_mount_point(mount_info info) {
    return info.root.starts_with("/adb/modules") || info.target.starts_with("/data/adb/modules");
}

}  // namespace

void mount_modules(std::vector<mount_info>& mount_infos, bool dry_run) {
    // We should filter the mount_infos before unmounting if the root directory presents
    if (mount_infos[0].target == "/") {
        mount_infos.erase(std::remove_if(mount_infos.begin(), mount_infos.end(),
                                         [](auto& info) { return !is_module_mount_point(info); }),
                          mount_infos.end());
    }

    // Verify that we won't mount again the root directory
    if (!dry_run && mount_infos[0].target != "/") {
        // Do remount
        std::vector<std::string> targets = {};
        for (auto& info : mount_infos) {
            magical_mount(info);
        }
    } else {
        LOGD("skip re-mount modules");
    }
}

bool update_mnt_ns(pid_t pid, bool clean, bool dry_run) {
    if (pid < 0) {
        LOGD("update mount namespace with an invalid pid %d", pid);
        return false;
    }

    std::string ns_path = zygiskd::UpdateMountNamespace(pid, clean);
    if (!ns_path.starts_with("/proc/")) {
        PLOGE("update mount namespace [%s]", ns_path.data());
        return false;
    }
    if (dry_run) return true;

    auto updated_ns = open(ns_path.data(), O_RDONLY);
    if (updated_ns >= 0) {
        LOGD("set mount namespace to [%s] fd=[%d]\n", ns_path.data(), updated_ns);
        setns(updated_ns, CLONE_NEWNS);
    } else {
        PLOGE("open mount namespace [%s]", ns_path.data());
    }
    close(updated_ns);
    return true;
}
