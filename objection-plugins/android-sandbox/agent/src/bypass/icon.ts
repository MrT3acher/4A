import { Switch } from "../lib/switch";

const $PackageManager = Java.use('android.app.ApplicationPackageManager')

function bypass()
{
    $PackageManager.setComponentEnabledSetting.overload('android.content.ComponentName', 'int', 'int').implementation = function(componentName, newState, flag) {
        var states = ['COMPONENT_ENABLED_STATE_DEFAULT', 'COMPONENT_ENABLED_STATE_ENABLED', 'COMPONENT_ENABLED_STATE_DISABLED', 'COMPONENT_ENABLED_STATE_DISABLED_USER', 'COMPONENT_ENABLED_STATE_DISABLED_UNTIL_USED']
        var flags = ['0', 'DONT_KILL_APP', 'SYNCHRONOUS', 'DONT_KILL_APP - SYNCHRONOUS']

        // COMPONENT_ENABLED_STATE_DISABLED = 2
        // DONT_KILL_APP = 1
        if (newState == 2 && flag == 1){
            var obj = {"plugin": "antianti", "part" : "Hide App", "real_value" :componentName + "\n" + states[newState] + "\n" + flags[flag], "return_value" : ""};
            send(JSON.stringify(obj));
            return;
        }
        else{
            var result = this.setComponentEnabledSetting(componentName, newState, flag);
            var obj = {"plugin": "antianti", "part" : "Hide App", "real_value" :componentName + "\n" + states[newState] + "\n" + flags[flag], "return_value" : componentName + "\n" + states[newState] + "\n" + flags[flag]};
            send(JSON.stringify(obj));
            return result;
        }
    }
}

function disable()
{
    $PackageManager.setComponentEnabledSetting.overload('android.content.ComponentName', 'int', 'int').implementation = null
}

export const icon = new Switch(bypass, disable)