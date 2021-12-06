import { Switch } from "../lib/switch";

const $TelephonyManager = Java.use('android.telephony.TelephonyManager')

function fake(imsi)
{
    $TelephonyManager.getSubscriberId.overload().implementation = function(){
        var result = this.getSubscriberId();
        var return_value = imsi;
        var obj = {"plugin": "faker", "part" : "IMSI Suscriber ID", "real_value" : result.toString(), "return_value" : return_value};
        send(JSON.stringify(obj));
        return return_value;
    }
}

function nonfake()
{
    $TelephonyManager.getSubscriberId.overload().implementation = null
}

export const imsi = new Switch(fake, nonfake)