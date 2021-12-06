import { files } from "./files";
import { firda } from "./frida";
import { icon } from "./icon";
import { process } from "./process";
import { sysproperties } from "./sysproperties";

export const bypass = {
    bypassFiles: files.up,
    bypassFrida: firda.up,
    bypassIcon: icon.up,
    bypassProcesss: process.up,
    bypassSysproperties: sysproperties.up
}

export const disableBypass = {
    disableBypassFiles: files.down,
    disableBypassFrida: firda.down,
    disableBypassIcon: icon.down,
    disableBypassProcesss: process.down,
    disableBypassSysproperties: sysproperties.down
}
