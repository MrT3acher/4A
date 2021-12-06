import { Hooker } from "./lib/hook"
import { stackTrace } from "./lib/thread";

var libcRemove, libcUnlink, libcRmdir

const $File = Java.use("java.io.File");

function hookDelete()
{
    libcRemove = Module.findExportByName('libc.so', 'remove')
    libcUnlink = Module.findExportByName('libc.so', 'unlink')
    libcRmdir = Module.findExportByName('libc.so', 'rmdir')

    const libcOriginalRemove = new NativeFunction(libcRemove, "int", ["pointer"])
    const libcOriginalUnlink = new NativeFunction(libcUnlink, "int", ["pointer"])
    const libcOriginalRmdir = new NativeFunction(libcRmdir, "int", ["pointer"])

    Interceptor.replace(libcRemove, new NativeCallback((pathname) => {
        var path = pathname.readCString();
        var stack = null;
        Java.perform(() => stack = stackTrace())
        var obj = {"plugin": "file", "method": "libc.so, remove", "name" : path, 'stack': stack.join('\n')};
        send(JSON.stringify(obj));

        return libcOriginalRemove(pathname) // call original function and return the result
    }, "int", ["pointer"]))


    Interceptor.replace(libcUnlink, new NativeCallback((pathname) => {
        var path = pathname.readCString();
        var stack = null;
        Java.perform(() => stack = stackTrace())
        var obj = {"plugin": "file", "method": "libc.so unlink", "name" : path, 'stack': stack.join('\n')};
        send(JSON.stringify(obj));

        return libcOriginalUnlink(pathname) // call original function and return the result
    }, "int", ["pointer"]))


    Interceptor.replace(libcRmdir, new NativeCallback((pathname) => {
        var path = pathname.readCString();
        var stack = null;
        Java.perform(() => stack = stackTrace())
        var obj = {"plugin": "file", "method": "libc.so rmdir", "name" : path, 'stack': stack.join('\n')};
        send(JSON.stringify(obj));

        return libcOriginalRmdir(pathname) // call original function and return the result
    }, "int", ["pointer"]))


    $File.delete.overload().implementation = function (s) {
        s = this.getAbsolutePath()
        var stack = stackTrace();
        var obj = {"plugin": "file", "method": "java.io.File delete", "name" : s, 'stack': stack.join('\n')};
        send(JSON.stringify(obj));
        return true; //pretend file was deleted
    }
}

function unhookDelete()
{
    Interceptor.revert(libcRemove)
    Interceptor.revert(libcUnlink)
    Interceptor.revert(libcRmdir)

    $File.delete.overload().implementation = null
}

function hookFile(){
    $File.$init.overload("java.lang.String").implementation = function(a0) {
        var ret = this.$init(a0);
        if (a0.length != 0){
            var stack = stackTrace();
            var obj = {"plugin": "file", "method": "File.$init('java.lang.String')", "name" : a0, 'stack': stack.join('\n')};
            send(JSON.stringify(obj));
        }
        return ret;
    }

    $File.$init.overload("java.lang.String", "java.lang.String").implementation = function(a0, a1) {
        var ret = this.$init(a0,a1);
        var stack = stackTrace();
        var obj = {"plugin": "file", "method": "File.$init('java.lang.String','java.lang.String')", "name" : a0+ "/" + a1, 'stack': stack.join('\n')};
        send(JSON.stringify(obj));
        return ret;
    }

    $File.isDirectory.overload().implementation = function() {
        var ret = this.isDirectory();
        if (this.toString().length != 0){
            var stack = stackTrace();
            var obj = {"plugin": "file", "method": "File.isDirectory()", "name" : this.toString(), 'stack': stack.join('\n')};
            send(JSON.stringify(obj));
        }
        return ret;
    }
}

function unhookFile()
{
    $File.$init.overload("java.lang.String").implementation = null
    $File.$init.overload("java.lang.String", "java.lang.String").implementation = null
    $File.isDirectory.overload().implementation = null
}

function hook()
{
    hookDelete()
    hookFile()
}

function unhook()
{
    unhookDelete()
    unhookFile()
}

export const file = new Hooker(hook, unhook)