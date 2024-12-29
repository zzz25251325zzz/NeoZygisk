# NeoZygisk

NeoZygisk is a Zygote injection module implemented using `ptrace`, which provides Zygisk API support for KernelSU and serves as a replacement of Magisk's built-in Zygisk.

## Requirements

### General

+ No multiple root implementation installed

### KernelSU

+ Minimal KernelSU version: 10940
+ Minimal KernelSU Manager (ksud) version: 11424
+ Kernel has full SELinux patch support

### Magisk

+ Minimal version: 26402
+ Built-in Zygisk turned off

## Design goals

1. NeoZygisk always synchronises with the [Magisk built-in Zygisk](https://github.com/topjohnwu/Magisk/tree/master/native/src/core/zygisk) API design, which are copied into the source folder [injector](https://github.com/JingMatrix/NeoZygisk/tree/master/loader/src/injector).
2. NeoZygisk aims to provide a minimalist implementation of Zygisk API; unnecessary features are thus not considered.
3. NeoZygisk guarantees to clean its injection trace inside applications processes once all Zygisk modules are unloaded.
4. NeoZygisk helps to hide the traces of root solutions through its design of DenyList, as explained below.

### DenyList

Current root solutions of Android are implemented in a systmeless way, meaning that they overlay the filesystems of the device by [mounting](https://man7.org/linux/man-pages/man8/mount.8.html) instead of overwriting the actual file contents. `DenyList` is designed to help the mounting trace hiding, which provides the following controls over how [mount namespaces](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html) are defined for app processes.

1. For applications granted with root privilege, both root solutions mount points and modules mount points are present in their mount namespaces.
2. For applications without root privilege and not on the DenyList, only modules mount points are present in their mount namespaces. As an example, this is the ideal configuration for applying font customization modules to their target applications.
3. For applications on the DenyList, their root privilege will be dropped even granted intentionally. A clean mount namespace will be provided for them to hide the traces of root solutions.
