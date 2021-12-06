import { Switch } from "../lib/switch"
import { stackTrace } from "./lib/thread"

const $ObjectOutputStream = Java.use('java.io.ObjectOutputStream')
const $ObjectInputStream = Java.use('java.io.ObjectInputStream')

function hook()
{
    $ObjectOutputStream.writeObject.overload('java.lang.Object').implementation = function(var0){
        var result = this.writeObject(var0)
        var stack = stackTrace()
        var obj = {"plugin": "serialize", "method": "ObjectOutputStream.writeObject('java.lang.Object')",
            "class": var0.getClass(), 'object': var0.toString(), 'serialized': this.toString(), 'stack': stack.join('\n')}
        send(JSON.stringify(obj))
        return result
    }

    $ObjectInputStream.readObject.overload().implementation = function(){
        var result = this.readObject()
        var stack = stackTrace()
        var obj = {"plugin": "serialize", "method": "ObjectInputStream.readObject()",
            "class": result.getClass(), 'object': result.toString(), 'stack': stack.join('\n')}
        send(JSON.stringify(obj))
        return result
    }
}

function unhook()
{
    $ObjectOutputStream.writeObject.overload('java.lang.Object').implementation = null
    $ObjectInputStream.readObject.overload().implementation = null
}

export const serialize = new Switch(hook, unhook)