const $SystemProperties = Java.use('android.os.SystemProperties')

var faked = {}

function fake(property, value)
{
    if (Object.keys(faked).length == 0)
    {
        $SystemProperties.get.overload('java.lang.String').implementation = function(prop) {
            var result = this.get(prop);
            if (prop in faked){
                var return_value = faked[prop]
                var obj = {"plugin": "faker", "part": 'System Property', "property": prop.toString(), "real_value" : result.toString(), "return_value" : return_value.toString()};
                send(JSON.stringify(obj));
                return return_value;
            }
            return this.get(prop);
        }
    }
    faked[property] = value
}

function nonfake(property)
{
    if (faked.hasOwnProperty(property))
    {
        delete faked[property]
        if (Object.keys(faked).length == 0)
        {
            $SystemProperties.get.overload('java.lang.String').implementation = null
        }
    }
}

// export const sysproperty = new Switch(fake, nonfake)
export const sysproperty = {
    fake: fake,
    nonfake: nonfake
}