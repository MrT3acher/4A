import { Switch } from "../lib/switch";
import { stackTrace } from "./lib/thread";

const $WebView = Java.use("android.webkit.WebView")

function hook()
{
    $WebView.loadUrl.overload("java.lang.String").implementation = function (s) {
        var stack = stackTrace()
        var obj = {"plugin": "webview", "method": "WebView.loadUrl('java.lang.String')", "url": s, 'stack': stack.join('\n')}
        send(JSON.stringify(obj))
        var result = this.loadUrl(s)
        return result
    }
}

function unhook()
{
    $WebView.loadUrl.overload("java.lang.String").implementation = null
}

export const webview = new Switch(hook, unhook)