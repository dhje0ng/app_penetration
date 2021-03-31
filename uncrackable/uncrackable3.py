#!/usr/bin/python3

import frida, sys

APP_NAME = "owasp.mstg.uncrackable3"

def on_message(message, data):
    print(message)

hook = """
    Interceptor.attach(Module.getExportByName("libc.so", "strstr"), {
        onEnter: function(args){
            var haystack = Memory.readUtf8String(args[0]);
            if(haystack.indexOf("frida") !== -1 || haystack.indexOf("xposed") !== -1){
                this.frida = Boolean(1);
            }
        },

        onLeave : function(retval){
            if(this.frida){
                retval.replace(0);
            }
            return retval;
        }
    });

    Java.perform(function(){
        var sys = Java.use("java.lang.System");
        sys.exit.implementation = function(){
            send("System.exit() Hooked!");
        };

        var main = Java.use("sg.vantagepoint.uncrackable3.MainActivity");
        main.onStart.overload().implementation = function(){
            send("mainactivity loaded!");
            var ret = this.onStart.overload().call(this);
        };
        libhook();
    });

    function libhook(){
        var funoffset = 0x000010e0;
        var lib = Module.findBaseAddress("libfoo.so");
        var libfun = lib.add(funoffset);
        if(!lib){
            send("libfoo.so file is nullptr");
        }
        send("libfoo.so baseaddr : " + lib.toString());
        
        Interceptor.attach(libfun, {
            onEnter: function(args){
                this.key = args[0];
                send("onEnter() Method Called!");
            },
            onLeave: function(args){
                console.log(Memory.readByteArray(this.key, 24));
                send("onLeave() Method Called!");
            }
        });
    }
"""

if __name__ == "__main__":
    try:
        process = frida.get_usb_device(timeout=5)
        pid = process.spawn(APP_NAME)
        run = process.attach(pid)
        process.resume(pid)
        script = run.create_script(hook)
        script.on('message', on_message)
        print("[*] Start Injection")
        script.load()
        sys.stdin.read()
        process.detach()
    except Exception as e:
        print(e)
