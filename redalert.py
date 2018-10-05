import lxml.etree as etree
from androguard.core.bytecodes import apk
import sys


def main():
  # python x.py name.apk
  a = apk.APK(sys.argv[1])
  a2 = a.get_android_resources()
  b = etree.fromstring(a2.get_string_resources(a.get_package()))
  for i in b:
      if i.attrib['name'] == 'domain':
        print(i.text)
        break


main()
