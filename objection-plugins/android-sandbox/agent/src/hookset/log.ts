import { Hooker } from "./lib/hook"
import { stackTrace } from "./lib/thread";

const $Log = Java.use("android.util.Log");
const logMethods = ['d', 'e', 'i', 'v', 'w'];

function hook()
{
    logMethods.forEach(function(method, i) {
        $Log[method].overload('java.lang.String','java.lang.String').implementation = function(tag, msg) {
            var stack = stackTrace();
            var obj = {"plugin": "log", "method": "Log."+method+"('java.lang.String','java.lang.String')", "tag": tag, "message" : msg, 'stack': stack.join('\n')};
            send(JSON.stringify(obj));
            var ret = this[method](tag, msg);
            return ret;
        }
        $Log[method].overload('java.lang.String','java.lang.String','java.lang.Throwable').implementation = function(tag, msg, th) {
            var stack = stackTrace();
            var obj = {"plugin": "log", "method":"Log."+method+"('java.lang.String','java.lang.String','java.lang.Throwable')", "tag": tag, "message" : msg, 'stack': stack.join('\n')};
            send(JSON.stringify(obj));
            var ret = this[method](tag, msg, th);
            return ret;
        } 
    });
}

function unhook()
{
    logMethods.forEach(function(method, i) {
        $Log[method].overload('java.lang.String', 'java.lang.String').implementation = null
        $Log[method].overload('java.lang.String', 'java.lang.String', 'java.lang.Throwable').implementation = null
    });
}

export const log = new Hooker(hook, unhook)