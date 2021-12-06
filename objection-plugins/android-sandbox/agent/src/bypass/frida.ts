import { Switch } from "../lib/switch";

var libcStrstr

function bypass()
{
    libcStrstr = Module.findExportByName("libc.so", "strstr")

    const libcOriginalStrstr = new NativeFunction(libcStrstr, "int", ["pointer"])

    Interceptor.replace(libcStrstr, new NativeCallback((haystack, needle) => {
        var haystackstr = haystack.readCString();
        var needlestr = needle.readCString();
        var searchForFrida = false

        if (needlestr.indexOf("frida") !== -1 || needlestr.indexOf("xposed") !== -1) {
            searchForFrida = true
        }

        if (searchForFrida) {
            return new NativePointer(0) // not found :D
        }

        return libcOriginalStrstr(haystack, needle);
    }, 'pointer', ['pointer', 'pointer']))
}

function disable()
{
    Interceptor.revert(libcStrstr)
}

export const firda = new Switch(bypass, disable)