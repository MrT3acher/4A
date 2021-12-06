//@ts-nocheck
import { Hooker } from "./lib/hook";

const $String = Java.use('java.lang.String');
const $StringBuilder = Java.use('java.lang.StringBuilder');

function hook()
{
    $String.toString.implementation = function(){
        const x  = this.toString()
        if(x.length > 5){
            var obj = {"plugin": "strings", "string" : x};
            send(JSON.stringify(obj))
        }
        return x
    }   

    $StringBuilder.toString.implementation = function(){
        const x = this.toString()
        if(x.length > 5){
            var obj = {"plugin": "strings", "string" : x};
            send(JSON.stringify(obj))
        }
        return x
    }

}

function unhook()
{
    $String.toString.implementation = null
    $StringBuilder.toString.implementation = null
}

export const strings = new Hooker(hook, unhook)