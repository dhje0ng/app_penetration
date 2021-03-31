#!/usr/bin/python3

import frida, sys

APP_NAME = "owasp.mstg.uncrackable2"

def on_message(message, data):
    print(message)

def main(process):
    hook = """
        Java.perform(function(){
            var exit_class = Java.use('java.lang.System');
            var debug_class = Java.use('android.os.Debug');

            exit_class.exit.implementation = function(){
                console.log("System exit() Hooked!");
            }

            debug_class.isDebuggerConnected.implementation = function(){
                console.log("Debug Hooked!");
                return true;
            }


        Interceptor.attach(Module.getExportByName("libfoo.so", "strncmp"), {
            onEnter: function(args){
                if(args[2].toInt32() == 23 && Memory.readCString(args[0], 23) == "12345678901234567890123"){
                    console.log("Find Key! : " + Memory.readCString(args[1]));
                }
            }
        })
    });
    """

    script = process.create_script(hook)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()
    process.detach()

if __name__ == "__main__":
    try:
        process = frida.get_usb_device().attach(APP_NAME)
        main(process)
    except Exception as e:
        print(e)
