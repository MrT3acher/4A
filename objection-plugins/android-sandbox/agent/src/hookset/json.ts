import { Hooker } from "./lib/hook";

const $JSONObject = Java.use("org.json.JSONObject");
const $JSONArray = Java.use("org.json.JSONArray");

const jsonClasses = [$JSONObject, $JSONArray];

function hook()
{
    jsonClasses.forEach(function(jsonClass, i) {
        jsonClass.$init.overload('java.lang.String').implementation = function(str){
            var result = this.$init(str);
            var obj = {"plugin": "json", "method": jsonClass.toString() + ".$init('java.lang.String')", "value" : str};
            send(JSON.stringify(obj));
            return result;
        }
    });
}

function unhook()
{
    jsonClasses.forEach(function(jsonClass, i) {
        jsonClass.$init.overload('java.lang.String').implementation = null
    });
}

export const json = new Hooker(hook, unhook)
