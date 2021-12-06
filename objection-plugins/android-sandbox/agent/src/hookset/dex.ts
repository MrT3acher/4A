import { Hooker } from "./lib/hook"
import { stackTrace } from "./lib/thread";

var dexclassloader = {
    'id' : '',
    'dexPath' : '',
    'optimizedDirectory' : '',
    'librarySearchPath': '',
    'parent': '',
    'class': ''
}
const getMethods = ['getDeclaredMethod', 'getMethod'];

const $DexClassLoader = Java.use("dalvik.system.DexClassLoader");
const $Class = Java.use('java.lang.Class');
const $ClassLoader = Java.use('java.lang.ClassLoader');

function hook()
{
    $DexClassLoader.$init.implementation = function(dexPath, optimizedDirectory, librarySearchPath, parent){
        var result = this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
        dexclassloader['id'] = this.hashCode();
        dexclassloader['dexPath'] = dexPath;
        dexclassloader['optimizedDirectory'] = optimizedDirectory;
        dexclassloader['librarySearchPath'] = librarySearchPath;
        if (parent == null){
            dexclassloader['parent'] = 'null';
        }
        else{
            dexclassloader['parent'] = parent.toString();
        }
        var stack = stackTrace();
        var obj = {"plugin": "dex", "dexPath": dexclassloader['dexPath'], "optimizedDirectory": dexclassloader['optimizedDirectory'], "librarySearchPath": dexclassloader['librarySearchPath'], "parent": dexclassloader['parent'], "entrypoint": 'NULL', 'stack': stack.join('\n')};
        send(JSON.stringify(obj));
        return result;
    }

    $ClassLoader.loadClass.overload('java.lang.String', 'boolean').implementation = function(name, resolve){
        var result = this.loadClass(name, resolve);
        if (this.hashCode() == dexclassloader['id']){
            dexclassloader['class'] = name;
        }
        return result;
    }

    $ClassLoader.loadClass.overload('java.lang.String').implementation = function(name){
        var result = this.loadClass(name);
        if (this.hashCode() == dexclassloader['id']){
            dexclassloader['class'] = name;
        }
        return result;
    }

    getMethods.forEach(function(method, i) {
        $Class[method].overload('java.lang.String', '[Ljava.lang.Class;').implementation = function(name, parameterTypes){

            var new_parameterTypes = '';
            if (parameterTypes != null){
                new_parameterTypes = parameterTypes.toString().replace(' ', ', ');
            }

            if (this.getName() == dexclassloader['class']){
                var stack = stackTrace();
                var entrypoint = this.getName() + "." + name + "(" + new_parameterTypes + ")";
                var obj = {"plugin": "dex", "dexPath": dexclassloader['dexPath'], "optimizedDirectory": dexclassloader['optimizedDirectory'], "librarySearchPath": dexclassloader['librarySearchPath'], "parent": dexclassloader['parent'], "entrypoint": entrypoint, 'stack': stack.join('\n')};
                send(JSON.stringify(obj));

                // Reset dexclassloader dict
                for (var i in dexclassloader) {
                    dexclassloader[i] = '';
                }
            }
            return this[method](name, parameterTypes);
        }
    });
}

function unhook()
{
    $DexClassLoader.$init.implementation = null
    $ClassLoader.loadClass.overload('java.lang.String', 'boolean').implementation = null
    $ClassLoader.loadClass.overload('java.lang.String').implementation = null
    getMethods.forEach((method, i) => {
        $Class[method].overload('java.lang.String', '[Ljava.lang.Class;').implementation = null
    });
}

export const dex = new Hooker(hook, unhook)