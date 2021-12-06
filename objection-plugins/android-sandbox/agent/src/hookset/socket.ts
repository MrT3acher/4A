import { Hooker } from "./lib/hook"
import { stackTrace } from "./lib/thread";

const $ServerSocket = Java.use('java.net.ServerSocket');
const $Socket = Java.use('java.net.Socket');
const $LocalServerSocket =  Java.use('android.net.LocalServerSocket');
const $DatagramSocket = Java.use('java.net.DatagramSocket');

function hook()
{
    $ServerSocket.accept.overload().implementation = function(){
        var result = this.accept();
        var stack = stackTrace();
        var obj = {"plugin": "socket", "method" : "ServerSocket.accept()", "value": this.toString(), 'stack': stack.join('\n')};
        send(JSON.stringify(obj));
        return result;
    }

    $Socket.$init.overload('java.lang.String', 'int').implementation = function(host, port){
        var stack = stackTrace();
        var result = this.$init(host, port);
        var msg = host + ":" + port;
        var obj = {"plugin": "socket", "method" : "Socket.$init('java.lang.String', 'int')", "value": msg, 'stack': stack.join('\n')};
        send(JSON.stringify(obj));
        return result;
    }

    $Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function(p_endpoint, p_timeout){
        var stack = stackTrace();
        var result = this.connect(p_endpoint, p_timeout);
        var msg = p_endpoint.toString() + "\n Timeout: " + p_timeout;
        var obj = {"plugin": "socket", "method" : "Socket.connect('java.net.SocketAddress', 'int')", "value": msg, 'stack': stack.join('\n')};
        send(JSON.stringify(obj));
        return result;
    }

    $Socket.connect.overload('java.net.SocketAddress').implementation = function(p_endpoint){
        var stack = stackTrace();
        var result = this.connect(p_endpoint);
        var obj = {"plugin": "socket", "method" : "Socket.connect('java.net.SocketAddress')", "value": p_endpoint.toString(), 'stack': stack.join('\n')};
        send(JSON.stringify(obj));
        return result;
    }

    $LocalServerSocket.accept.overload().implementation = function(){
        var stack = stackTrace();
        var result = this.accept();
        var obj = {"plugin": "socket", "method" : "LocalServerSocket.accept()", "value": this, 'stack': stack.join('\n')};
        send(JSON.stringify(obj));
        return result;
    }

    $DatagramSocket.connect.overload('java.net.InetAddress','int').implementation = function(address, port){
        var stack = stackTrace();
        var result = this.connect(address, port);
        var msg = address + ":" + port;
        var obj = {"plugin": "socket", "method" : "DatagramSocket.connect('java.net.InetAddress','int')", "value": msg, 'stack': stack.join('\n')};
        send(JSON.stringify(obj));
        return result;
    }

}

function unhook()
{
    $ServerSocket.accept.overload().implementation = null
    $Socket.$init.overload('java.lang.String', 'int').implementation = null
    $Socket.connect.overload('java.net.SocketAddress', 'int').implementation = null
    $Socket.connect.overload('java.net.SocketAddress').implementation = null
    $LocalServerSocket.accept.overload().implementation = null
    $DatagramSocket.connect.overload('java.net.InetAddress','int').implementation = null
}

export const socket = new Hooker(hook, unhook)