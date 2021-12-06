import { hasfile } from "../faker/hasfile"
import { Switch } from "../lib/switch"

const vmfiles = [
    "ueventd.android_x86.rc",
    "x86.prop",
    "ueventd.ttVM_x86.rc",
    "init.ttVM_x86.rc",
    "fstab.ttVM_x86",
    "fstab.vbox86",
    "init.vbox86.rc",
    "ueventd.vbox86.rc",
    "/dev/socket/qemud",
    "/dev/qemu_pipe",
    "/system/lib/libc_malloc_debug_qemu.so",
    "/sys/qemu_trace",
    "/system/bin/qemu-props",
    "/dev/socket/genyd",
    "/dev/socket/baseband_genyd",
    "/proc/tty/drivers",
    "/proc/cpuinfo"
]

function bypass()
{
    send('`antianti files` will use `faker hasfile`')
    for (var i in vmfiles)
    {
        hasfile.fake(i, false)
    }
}

function disable()
{
    for (var i in vmfiles)
    {
        hasfile.nonfake(i)
    }
}

export const files = new Switch(bypass, disable)