import { stackTrace } from "../hookset/lib/thread"

class Plugin
{
    name = null

    private hooks = []

    constructor(name: string)
    {
        this.name = name
    }

    addHook(clazz: string, method: string, vars: string[], stack = false)
    {
        var clazzName = clazz.split('.').pop()
        var pluginName = this.name
        var varsString = vars.join(', ')
        Java.perform(() => {
            Java.use(clazz)[method].overload(...vars).implementation = (...args) => {
                var obj = {}
                if (stack)
                    obj['stack'] = stackTrace()
                obj['plugin'] = pluginName
                obj['method'] = `${clazzName}.${method}(${varsString})`
                
            }
        })
    }
}