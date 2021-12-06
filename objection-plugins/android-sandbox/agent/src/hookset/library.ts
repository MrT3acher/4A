import { Hooker } from "./lib/hook";

var androidDlopenExt

/**
 * hook library run-time loader. it should be called a the beginning of the android app execution.
 */
function hook()
{
    androidDlopenExt = Module.findExportByName(null, 'android_dlopen_ext')

    const androidDlopenExtOriginal = new NativeFunction(androidDlopenExt, "pointer", ["pointer", "int", "pointer"])

    Interceptor.replace(androidDlopenExt, new NativeCallback((__filename, __flags, __info) => {
        var ret = androidDlopenExtOriginal(__filename, __flags, __info) // call original function and return the result

        var path = __filename.readCString();
        var obj = {"plugin": "library", "name" : path, "return": ret};
        send(JSON.stringify(obj));

        return ret
    }, "pointer", ["pointer", "int", "pointer"]))
}

function unhook()
{
    Interceptor.revert(androidDlopenExt)
}

export const library = new Hooker(hook, unhook)