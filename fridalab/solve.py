#!/usr/bin/python3

import frida, sys

APP_NAME = "uk.rossmarks.fridalab"

def on_message(message, data):
    print(message)

inject = """
    setImmediate(function(){
        Java.perform(function(){
            var chall1 = Java.use("uk.rossmarks.fridalab.challenge_01");
            chall1.chall01.value = 1;
        });
    });

    setImmediate(function(){
        Java.choose("uk.rossmarks.fridalab.MainActivity", {
            onMatch: function(instance){
                instance.chall02();
            },
            onComplete: function(){
                send("Create MainActivity.chall02()");
            }
        });
    });

    setImmediate(function(){
        Java.perform(function(){
            var chall3 = Java.use("uk.rossmarks.fridalab.MainActivity");
            chall3.chall03.implementation = function(){
                send("Return Variable Change to Chall03!");
                return true;
            }
        });
    });

    setImmediate(function(){
        Java.choose("uk.rossmarks.fridalab.MainActivity", {
            onMatch: function(instance){
                instance.chall04("frida");
            },
            onComplete: function(){
                send("Chall04 Called!");
            }
        });
    });

    setImmediate(function(){
        Java.perform(function(){
            var chall5 = Java.use("uk.rossmarks.fridalab.MainActivity");
            chall5.chall05.overload('java.lang.String').implementation = function(){
                this.chall05.call(this, "frida");
            }
        });
    });

    setImmediate(function(){
        Java.perform(function(){
            var chall6 = Java.use("uk.rossmarks.fridalab.challenge_06");
            chall6.addChall06.overload('int').implementation = function(args){
                Java.choose("uk.rossmarks.fridalab.MainActivity", {
                    onMatch: function(instance){
                        instance.chall06(chall6.chall06.value);
                    },
                    onComplete: function(){
                        send("Chall06 Called!");
                    }
                })
            }
        });
    });

    setImmediate(function(){
        Java.perform(function(){
            var chall7 = Java.use("uk.rossmarks.fridalab.challenge_07");
                Java.choose("uk.rossmarks.fridalab.MainActivity", {
                    onMatch: function(instance){
                        for(var i=0; i<10000; i++){
                            if(chall7.check07Pin(i.toString())){
                                instance.chall07(i.toString());
                            }
                        }
                    },
                    onComplete: function(){
                        send("Chall07 Called!");
                    }
                })
        })
    });

    setImmediate(function(){
        Java.choose("uk.rossmarks.fridalab.MainActivity", {
            onMatch: function(instance){
                var checkid = instance.findViewById(2131165231);
                var widget = Java.use("android.widget.Button");
                var call = Java.cast(checkid, widget);
                var string = Java.use("java.lang.String");
                call.setText(string.$new("Confirm"));
            },
            onComplete: function(){
                send("Chall08 Called!");
            }
        })
    });
"""

if __name__ == "__main__":
    try:
        process = frida.get_usb_device(timeout=5)
        pid = process.spawn(APP_NAME)
        run = process.attach(pid)
        process.resume(pid)
        script = run.create_script(inject)
        script.on('message', on_message)
        print("[*] Start Injection")
        script.load()
        sys.stdin.read()
        process.detach()
    except Exception as e:
        print(e)