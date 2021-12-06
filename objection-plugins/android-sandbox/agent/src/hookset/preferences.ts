import { Hooker } from "./lib/hook";

const $SharedPreferencesImpl = Java.use('android.app.SharedPreferencesImpl');
const $SharedPreferencesImpl$EditorImpl = Java.use('android.app.SharedPreferencesImpl$EditorImpl');

function hook()
{
  $SharedPreferencesImpl.$init.overload('java.io.File', 'int').implementation = function(file, mode) {
    var result = this.$init(file, mode);
    var obj = {"plugin": "preferences", "method": "SharedPreferencesImpl.$init('java.lang.String', 'int')", "file": file.getAbsolutePath(), "value": mode};
    send(JSON.stringify(obj));
    return result;
  }

  $SharedPreferencesImpl$EditorImpl.putString.overload('java.lang.String', 'java.lang.String').implementation = function(k, v) {
    var obj = {"plugin": "preferences", "method":"SharedPreferences.Editor.putString('java.lang.String', 'java.lang.String')", "file": 'NULL', "value": k+" = "+v};
    send(JSON.stringify(obj));
    return this.putString(k, v);
  }
}

function unhook()
{
  $SharedPreferencesImpl.$init.overload('java.io.File', 'int').implementation = null
  $SharedPreferencesImpl$EditorImpl.putString.overload('java.lang.String', 'java.lang.String').implementation = null
}

export const prefs = new Hooker(hook, unhook)