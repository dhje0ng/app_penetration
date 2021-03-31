#!/usr/bin/python3

import frida, sys

APP_NAME = "owasp.mstg.uncrackable1"

def on_message(message, data):
    print(message)

def main(process):
    hook1 = """
        Java.perform(function() {
            var exit_class = Java.use("java.lang.System");
            var equal_class = Java.use("java.lang.String");
            var secret_class = Java.use("sg.vantagepoint.a.a");

            exit_class.exit.implementation = function(){
                console.log("[*] System.exit() Hooking!");
            }

            equal_class.equals.implementation = function(arr1){
                console.log("[*] str.equals() Hooking!");
                console.log(arr1);
                return true;
            }

            secret_class.a.implementation = function(arr1, arr2){
                var retval = this.a(arr1, arr2);
                var secret_msg = "";

                for(var i=0; i < retval.length; i++){
                    secret_msg += String.fromCharCode(retval[i]);
                }

                console.log("[*] Secret Method Hooking!");
                console.log(secret_msg);
                return retval;
            }
        });
    """

    script = process.create_script(hook1)
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
