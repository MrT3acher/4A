import { Hooker } from "./lib/hook"

const $MessageDigest = Java.use("java.security.MessageDigest");

function hook()
{
    var mdId;
    var inputValue;

    $MessageDigest.update.overload('[B').implementation = function(input){
        var result = this.update(input);
        mdId = this.hashCode(); // method from Object
        inputValue = new ArrayBuffer(input);
        return result;
    }

    $MessageDigest.digest.overload().implementation = function(){
        var result = this.digest();
        if (this.hashCode() == mdId){
            var hexInput = Buffer.from(inputValue).toString('hex');
            var hexOutput = Buffer.from(new ArrayBuffer(result)).toString('hex');
            var obj = {"plugin": "hash", "algo" : this.getAlgorithm(), "input_value": hexInput, "output_value": hexOutput};
            send(JSON.stringify(obj));
            mdId = '';
            inputValue = '';
        }
        return result;
    }
}

function unhook()
{
    $MessageDigest.update.overload('[B').implementation = null
    $MessageDigest.digest.overload().implementation = null
}

export const hash = new Hooker(hook, unhook)