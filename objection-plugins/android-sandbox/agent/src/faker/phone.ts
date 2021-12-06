import { Switch } from "../lib/switch";

const $TelephonyManager = Java.use('android.telephony.TelephonyManager')

function fake(phone1, phone2)
{
    $TelephonyManager.getLine1Number.overload().implementation = function(){
        var result = this.getLine1Number();
        var return_value = phone1;
        var obj = {"plugin": "faker", "part" : "Phone number 1", "real_value" : result.toString(), "return_value" : return_value};
        send(JSON.stringify(obj));
        return return_value;
    }

    if (phone2)
    {
        $TelephonyManager.getLine2Number.overload().implementation = function(){
            var result = this.getLine1Number();
            var return_value = phone2;
            var obj = {"plugin": "faker", "part" : "Phone number 2", "real_value" : result.toString(), "return_value" : return_value};
            send(JSON.stringify(obj));
            return return_value;
        }
    }
}

function nonfake()
{
    $TelephonyManager.getLine1Number.overload().implementation = null
    $TelephonyManager.getLine2Number.overload().implementation = null
}

export const phone = new Switch(fake, nonfake)