import { Switch } from "../lib/switch";

const $ProcessBuilder = Java.use('java.lang.ProcessBuilder');

function bypass()
{
    $ProcessBuilder.$init.overload('[Ljava.lang.String;').implementation = function(x) {
        var result = this.$init(x);
        var return_value = undefined;
        var obj = {"plugin": "antianti", "part": "ProcessBuilder", "arg": x, "real_value" : result, "return_value" : return_value};
        send(JSON.stringify(obj));
        return return_value;
    }
}

function disable()
{
    $ProcessBuilder.$init.overload('[Ljava.lang.String;').implementation = null
}

export const process = new Switch(bypass, disable)