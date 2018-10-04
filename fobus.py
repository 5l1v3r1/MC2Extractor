import lxml.etree as etree
from androguard.core.bytecodes import apk
import sys

def main():
  # python x.py name.apk
  a = apk.APK(sys.argv[1])
  a2 = a.get_android_resources()
  b = etree.fromstring(a2.get_string_resources(a.get_package()))
  print(b[2].text)


main()