import { Hooker } from "./lib/hook"
import { stackTrace } from "./lib/thread";

const $Base64 = Java.use('android.util.Base64');

function hook()
{
    $Base64.decode.overload('java.lang.String', 'int').implementation = function(str, flag) {
        var result = this.decode(str, flag);
        if (result.length != 0) {
            var stack = stackTrace();
            var obj = {"plugin": "base64", "method" : "Base64.decode('java.lang.String', 'int')", 'stack': stack.join('\n')};
            send(JSON.stringify(obj), new ArrayBuffer(result));
        }
        return result;
    }
    $Base64.decode.overload('[B', 'int').implementation = function(input, flag) {
        var result = this.decode(input, flag);
        if (result.length != 0) {
            var stack = stackTrace();
            var obj = {"plugin": "base64", "method" : "Base64.decode('[B', 'int')", 'stack': stack.join('\n')};
            send(JSON.stringify(obj), new ArrayBuffer(result));
        }
        return result;
    }
    $Base64.decode.overload('[B', 'int', 'int', 'int').implementation = function(input, offset, len, flags){
        var result = this.decode(input, offset, len, flags);
        if (result.length != 0) {
            var stack = stackTrace();
            var obj = {"plugin": "base64", "method" : "Base64.decode('[B', 'int', 'int', 'int')", 'stack': stack.join('\n')};
            send(JSON.stringify(obj), new ArrayBuffer(result));
        }
        return result;
    }
    $Base64.encode.overload('[B', 'int').implementation = function(input, flags) {
        var result = this.encode(input, flags);
        if (input.length != 0) {
            var stack = stackTrace();
            var obj = {"plugin": "base64", "method" : "Base64.encode('[B', 'int')", 'stack': stack.join('\n')};
            send(JSON.stringify(obj), new ArrayBuffer(input));
        }
        return result;
    }
    $Base64.encode.overload('[B', 'int', 'int', 'int').implementation = function(input, offset, len, flags){
        var result = this.encode(input, offset, len, flags);
        if (input.length != 0) {
            var stack = stackTrace();
            var obj = {"plugin": "base64", "method" : "Base64.encode('[B', 'int', 'int', 'int')", 'stack': stack.join('\n')};
            send(JSON.stringify(obj), new ArrayBuffer(input));
        }
        return result;
    }
    $Base64.encodeToString.overload('[B', 'int', 'int', 'int').implementation = function(input, offset, len, flags){
        var result = this.encodeToString(input, offset, len, flags);
        if (input.length != 0) {
            var stack = stackTrace();
            var obj = {"plugin": "base64", "method" : "Base64.encodeToString('[B', 'int', 'int', 'int')",'stack': stack.join('\n')};
            send(JSON.stringify(obj), new ArrayBuffer(input));
        }
        return result;
    }
    $Base64.encodeToString.overload('[B', 'int').implementation = function(input, flags){
        var result = this.encodeToString(input, flags);
        if (input.length != 0) {
            var stack = stackTrace();
            var obj = {"plugin": "base64", "method" : "Base64.encodeToString('[B', 'int')",'stack': stack.join('\n')};
            send(JSON.stringify(obj), new ArrayBuffer(input));
        }
        return result;
    }
}

function unhook()
{
    $Base64.decode.overload('java.lang.String', 'int').implementation = null
    $Base64.decode.overload('[B', 'int').implementation = null
    $Base64.decode.overload('[B', 'int', 'int', 'int').implementation = null
    $Base64.encode.overload('[B', 'int').implementation = null
    $Base64.encode.overload('[B', 'int', 'int', 'int').implementation = null
    $Base64.encodeToString.overload('[B', 'int', 'int', 'int').implementation = null
    $Base64.encodeToString.overload('[B', 'int').implementation = null
}

export const base64 = new Hooker(hook, unhook)