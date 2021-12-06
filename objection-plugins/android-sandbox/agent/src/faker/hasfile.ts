const $File = Java.use("java.io.File")

var faked = {}

function fake(filepath, has = false)
{
    if (Object.keys(faked).length == 0)
    {
        $File.exists.implementation = function () {
            var path = this.getAbsolutePath();
    
            for(var i in faked){
                if(i == path){
                    var obj = {"plugin": "faker", "part" : "Has File", "real_value" : path.toString(), "return_value" : faked[i]};
                    send(JSON.stringify(obj));
                    return faked[i];
                }
            }
        
            return this.exists();
        }
    }
    faked[filepath] = has
}

function nonfake(filepath)
{
    if (faked.hasOwnProperty(filepath))
    {
        delete faked[filepath]
        if (Object.keys(faked).length == 0)
        {
            $File.exists.implementation = null
        }
    }
}

// export const hasfile = new Switch(fake, nonfake)
export const hasfile = {
    fake: (filepath, has) => Java.perform(() => fake(filepath, has)),
    nonfake: (filepath) => Java.perform(() => nonfake(filepath))
}