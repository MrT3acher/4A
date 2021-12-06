import { Switch } from "../lib/switch";

const $TelephonyManager = Java.use('android.telephony.TelephonyManager')

function fake(deviceId)
{
    $TelephonyManager.getDeviceId.overload().implementation = function(){
        var result = this.getDeviceId();
        var return_value = deviceId;
        var obj = {"plugin": "faker", "part" : "Device id", "real_value" : result.toString(), "return_value" : return_value};
        send(JSON.stringify(obj));
        return return_value
    }
}

function nonfake()
{
    $TelephonyManager.getDeviceId.overload().implementation = null
}

export const device = new Switch(fake, nonfake)