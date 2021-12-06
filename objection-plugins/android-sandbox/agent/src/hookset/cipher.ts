import { Hooker } from "./lib/hook"
import { stackTrace } from "./lib/thread";

const $Cipher = Java.use("javax.crypto.Cipher");
const $SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
const $IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");

function hookCipher()
{
    var cipherId;
    var keyInfo;
    var opmodeInfo;

    $Cipher.init.overload('int', 'java.security.Key').implementation = function (opmode, key) {
        cipherId = this.hashCode();
        keyInfo = key.getEncoded(); 
        opmodeInfo = opmode;
        return this.init(opmode, key);
    }

    $Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (opmode, key, params) {
        cipherId = this.hashCode();
        keyInfo = key.getEncoded(); 
        opmodeInfo = opmode;
        return this.init(opmode, key, params);
    }

    $Cipher.doFinal.overload("[B").implementation = function (barr) {
        var result = this.doFinal(barr);
        if (cipherId == this.hashCode()){
            var hexKey  = Buffer.from(new ArrayBuffer(keyInfo)).toString('hex');
            var hexIV = Buffer.from(new ArrayBuffer(this.getIV())).toString('hex');
            var hexArg = Buffer.from(new ArrayBuffer(barr)).toString('hex');
            var hexResult = Buffer.from(new ArrayBuffer(result)).toString('hex');

            var stack = stackTrace();
            var obj = {"plugin": "cipher", "algo" : this.getAlgorithm(), "iv" : hexIV, "opmode" : opmodeInfo, "key": hexKey, "arg": hexArg, "result": hexResult, 'stack': stack.join('\n')};
            send(JSON.stringify(obj));

            cipherId = '';
            keyInfo = '';
            opmodeInfo = '';          
        }
        return result;
    }
}

function unhookCipher()
{
    $Cipher.init.overload('int', 'java.security.Key').implementation = null
    $Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = null
    $Cipher.doFinal.overload("[B").implementation = null
}

function hookSecret() 
{    
    $SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (x, y) {
        var obj = {"plugin": "key"};
        send(JSON.stringify(obj), new ArrayBuffer(x));
        return this.$init(x, y);
    }

    $IvParameterSpec.$init.overload("[B").implementation = function (x) {
        var obj = {"plugin": "iv"};
        send(JSON.stringify(obj), new ArrayBuffer(x));
        return this.$init(x);
    }
}

function unhookSecret() 
{    
    $SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = null
    $IvParameterSpec.$init.overload("[B").implementation = null
}

function hook()
{
    hookCipher()
    hookSecret()
}

function unhook()
{
    unhookCipher()
    unhookSecret()
}

export const cihper = new Hooker(hook, unhook)