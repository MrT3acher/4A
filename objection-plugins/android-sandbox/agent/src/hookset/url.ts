import { Hooker } from "./lib/hook"
import { stackTrace } from "./lib/thread";

const $URL = Java.use("java.net.URL");
const $HttpURLConnection = Java.use('java.net.HttpURLConnection');
const $URLConnection = Java.use('java.net.URLConnection');
const $HttpURLConnectionImpl = Java.use('com.android.okhttp.internal.huc.HttpURLConnectionImpl');

const URLConnectionClasses = [$HttpURLConnectionImpl, $HttpURLConnection, $URLConnection];

function hook()
{
    $URL.$init.overload('java.lang.String').implementation = function (var0) {
        var stack = stackTrace()

        if(! var0.startsWith("null")){
            var obj = {"plugin": "url", "url" : var0, 'stack': stack.join('\n') + '\n', "req_method" : "NULL"};
            send(JSON.stringify(obj))
        }
        return this.$init(var0);
    };

    URLConnectionClasses.forEach(URLClass => {
        URLClass.connect.overload().implementation = function(){
            var stack = stackTrace()
            var obj = {"plugin": "url", "url" : this.getURL().toString(), 'stack': stack.join('\n') + '\n', "req_method" : this.getRequestMethod()};
            send(JSON.stringify(obj));
            return this.connect();
        }
    });

    $URL.openConnection.overload().implementation = function(){
        var result = this.openConnection();
        var stack = stackTrace()
        // Cannot retrieve directly the req method, by default GET
        var obj = {"plugin": "url", "url_id": result.hashCode(), "url" : result.getURL().toString(), 'stack': stack.join('\n') + '\n', "req_method" : 'NULL'};
        send(JSON.stringify(obj))
        return result;
    }

}

function unhook()
{
    $URL.$init.overload('java.lang.String').implementation = null
    URLConnectionClasses.forEach(URLClass => {
        URLClass.connect.overload().implementation = null
    });
    $URL.openConnection.overload().implementation = null
}

export const url = new Hooker(hook, unhook)