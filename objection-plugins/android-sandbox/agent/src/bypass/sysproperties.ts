import { sysproperty } from "../faker/sysproperty"
import { Switch } from "../lib/switch"

const properties = {
    "init.svc.qemud": null,
    "init.svc.qemu-props": null,
    "qemu.hw.mainkeys": null,
    "qemu.sf.fake_camera": null,
    "qemu.sf.lcd_density": null,
    "ro.bootloader": "xxxxx",
    "ro.bootmode": "xxxxxx",
    "ro.hardware": "xxxxxx",
    "ro.kernel.android.qemud": null,
    "ro.kernel.qemu.gles": null,
    "ro.kernel.qemu": "xxxxxx",
    "ro.product.device": "xxxxx",
    "ro.product.model": "xxxxxx",
    "ro.product.name": "xxxxxx",
    "ro.serialno": null,
    "init.svc.gce_fs_monitor": "xxxxxx",
    "init.svc.dumpeventlog": "xxxxxx",
    "init.svc.dumpipclog": "xxxxxx",
    "init.svc.dumplogcat": "xxxxxx",
    "init.svc.dumplogcat-efs": "xxxxxx",
    "init.svc.filemon": "xxxxxx",
    "ro.hardware.virtual_device": "xxxxx",
    "ro.kernel.androidboot.hardware": "xxxxx",
    "ro.boot.hardware": "xxxxx",
    "ro.boot.selinux": "enable",
    "ro.factorytest": "xxxxxx",
    "ro.kernel.android.checkjni": "xxxxxx",
    "ro.build.product": "xxxxx",
    "ro.product.manufacturer": "xxxxx",
    "ro.product.brand": "xxxxx",
    "init.svc.vbox86-setup": null,
    "init.svc.goldfish-logcat": null,
    "init.svc.goldfish-setup": null,
}

function bypass()
{
    send('`antianti sysproperties` will use `faker property`')
    for (var i in properties)
    {
        sysproperty.fake(i, properties[i])
    }
}

function disable()
{
    for (var i in properties)
    {
        sysproperty.nonfake(i)
    }
}

export const sysproperties = new Switch(bypass, disable)