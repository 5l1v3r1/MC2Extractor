import os
from androguard.core.bytecodes import apk
import frida
import time
__author__ = "@eybisi"
device = frida.get_usb_device()
files = [f for f in os.listdir("./")]
for f in files:
    print(f)
    a = apk.APK(f)
    os.system("adb install "+f)
    print(f + " installed ")
    pid = device.spawn([a.get_package()])
    session = device.attach(pid)
    script = session.create_script(open("../../frida-utils/del.js").read())
    script.load()
    device.resume(pid)
    time.sleep(2) 
    os.system("adb pull /data/data/"+a.get_package()+" .")
    print("Decrypted dex pulled")
    script.unload()
    os.system("adb uninstall "+a.get_package())
    print(f + " uninstalled")
    time.sleep(2)
