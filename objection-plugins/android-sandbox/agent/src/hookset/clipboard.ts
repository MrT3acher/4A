import { Switch } from "../lib/switch";
import { stackTrace } from "./lib/thread";

const $ClipData = Java.use('android.content.ClipData')

function hook()
{
    $ClipData.getItemAt.overload('int').implementation = function(index){
        var result = this.getItemAt(index)
        var stack = stackTrace()
        var obj = {"plugin": "clipboard", "method": "ClipData.getItemAt('int')",
            "data": result, 'index': index, 'stack': stack.join('\n')}
        send(JSON.stringify(obj))
        return result
    }

    $ClipData.newPlainText.overload('java.lang.CharSequence', 'java.lang.CharSequence').implementation = function(label, text){
        var stack = stackTrace()
        var obj = {"plugin": "clipboard", "method": "ClipData.newPlainText('java.lang.CharSequence', 'java.lang.CharSequence')",
            "label": label, 'text': text, 'stack': stack.join('\n')}
        send(JSON.stringify(obj))
        var result = this.newPlainText(label, text)
        return result
    }
    // TODO: hook other new* methods, like newIntent, newHtmlText, ...
}
function unhook()
{
    $ClipData.getItemAt.overload('int').implementation = null
    $ClipData.newPlainText.overload('java.lang.CharSequence', 'java.lang.CharSequence').implementation = null
}

export const clipboard = new Switch(hook, unhook)