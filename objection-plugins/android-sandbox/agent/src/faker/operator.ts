import { Switch } from "../lib/switch";

const $TelephonyManager = Java.use('android.telephony.TelephonyManager')
const telephonyManagerMethods = ['getSimOperatorName', 'getSimOperator'];

function fake(network, operator, iso)
{
    $TelephonyManager.getNetworkOperatorName.overload().implementation = function(){
        var result = this.getNetworkOperatorName();
        var return_value = network;
        var obj = {"plugin": "faker", "part" : "Network Operator Name", "real_value" : result.toString(), "return_value" : return_value};
        send(JSON.stringify(obj));
        return return_value;
    }

    telephonyManagerMethods.forEach(function(method, i) {
        $TelephonyManager[method].overload().implementation = function() {
            var result = this[method]();
            var obj = {"plugin": "faker", "part" : "Sim Operator", "real_value" : result.toString(), "return_value" : operator};
            send(JSON.stringify(obj));
            return operator;
        }
    })

    $TelephonyManager.getNetworkCountryIso.overload('int').implementation = function(slotIndex) {
        var result = this.getNetworkCountryIso(slotIndex);
        var obj = {"plugin": "faker", "part" : "Network Country Iso", "real_value" : result.toString(), "return_value" : iso};
        send(JSON.stringify(obj));
        return iso;
    };
    $TelephonyManager.getNetworkCountryIso.overload().implementation = function(){
        var result = this.getNetworkCountryIso();
        var obj = {"plugin": "faker", "part" : "Network Country Iso", "real_value" : result.toString(), "return_value" : iso};
        send(JSON.stringify(obj));
        return iso;
    }
}

function nonfake()
{
    $TelephonyManager.getNetworkOperatorName.overload().implementation = null
    telephonyManagerMethods.forEach(function(method, i) {
        $TelephonyManager[method].overload().implementation = null
    })
    $TelephonyManager.getNetworkCountryIso.overload('int').implementation = null
    $TelephonyManager.getNetworkCountryIso.overload().implementation = null
}

export const operator = new Switch(fake, nonfake)