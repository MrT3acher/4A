import { Switch } from "../lib/switch"

const $Location = Java.use('android.location.Location')

function fake(lat = 48.8534, long = 2.3488)
{
    var location = $Location.$new("gps")
    location.setLatitude(lat)
    location.setLongitude(long)

    $Location.$init.overload("android.location.Location").implementation = function(x) {
        var result = this.$init(x);
        var obj = {"plugin": "faker", "part" : "Location Init", "real_value" : result.toString(), "return_value" : location.toString()};
        send(JSON.stringify(obj));
        return location
    }

    $Location.$init.overload("java.lang.String").implementation = function(x){
        var result = this.$init(x);
        var obj = {"plugin": "faker", "part" : "Location Init", "real_value" : result.toString(), "return_value" : location.toString()};
        send(JSON.stringify(obj));
        return location
    }

    $Location.getLatitude.implementation = function(){
        var result = this.getLatitude();
        var obj = {"plugin": "faker", "part" : "Location Latitude", "real_value" : result, "return_value" : lat};
        send(JSON.stringify(obj));
        return lat
    }

    $Location.getLongitude.implementation = function(){
        var result = this.getLongitude();
        var obj = {"plugin": "faker", "part" : "Location Longitude", "real_value" : result, "return_value" : long};
        send(JSON.stringify(obj));
        return long
    }
}

function nonfake()
{
    $Location.$init.overload("android.location.Location").implementation = null
    $Location.$init.overload("java.lang.String").implementation = null
    $Location.getLatitude.implementation = null
    $Location.getLongitude.implementation = null
}

export const location = new Switch(fake, nonfake)