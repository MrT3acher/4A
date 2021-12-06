import { Hooker } from "./lib/hook";

const $System = Java.use('java.lang.System')
const $Proxy = Java.use('android.net.Proxy')

function hook()
{
    $System.getProperty.overload('java.lang.String').implementation = function(p_str){
        if (p_str.includes("http.proxyHost") || p_str.includes("https.proxyHost") ){
            var obj = {"plugin": "proxy", "method": "http[s].proxyHost"};
            send(JSON.stringify(obj));
            return null;
        }
        else if (p_str.includes("http.proxyPort") || (p_str.includes("https.proxyPort"))){
            var obj = {"plugin": "proxy", "method": "http[s].proxyPort"};
            send(JSON.stringify(obj));
            return null;
        }
        else{
            return this.getProperty(p_str);
        }
    }
    $Proxy.getHost.overload('android.content.Context').implementation = function(p_str){
        var obj = {"plugin": "proxy", "method": "android.net.Proxy.getHost"};
        send(JSON.stringify(obj));
        return null;
    }
    $Proxy.getPort.overload('android.content.Context').implementation = function(p_str){
        var obj = {"plugin": "proxy", "method": "android.net.Proxy.getPort"};
        send(JSON.stringify(obj));
        return null;
    }
}

function unhook()
{
    $System.getProperty.overload('java.lang.String').implementation = null
    $Proxy.getHost.overload('android.content.Context').implementation = null
    $Proxy.getPort.overload('android.content.Context').implementation = null
}

export const proxy = new Hooker(hook, unhook)