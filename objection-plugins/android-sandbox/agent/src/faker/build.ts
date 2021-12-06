import { Switch } from "../lib/switch"

// Class containing const that we want to modify
const $Build = Java.use("android.os.Build")

var defaultFields = {}

function replaceField(fieldName, value)
{
    var field = $Build.class.getDeclaredField(fieldName)
    var result = field.get($Build.class);
    if (!defaultFields[fieldName])
        defaultFields[fieldName] = result.toString();
    // var obj = {"plugin": "bypass", "property" : "Build Properties", "real_value" : fieldName.toString() + " = " + result.toString(), "return_value" : fieldName.toString() + " = " + value.toString()};
    // send(JSON.stringify(obj));
    field.setAccessible(true);
    field.set(null, value);
}
function replaceFields(fields)
{
    for (let i in fields) {
        replaceField(i, fields[i])
    }
}

function fake(fields)
{
    replaceFields(fields)
}

function nonfake()
{
    replaceFields(defaultFields)
}

export const build = new Switch(fake, nonfake)