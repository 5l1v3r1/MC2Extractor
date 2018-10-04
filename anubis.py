import requests
import binascii
from bs4 import BeautifulSoup
from os import popen, chdir, path, devnull, walk, getcwd
import base64
import sys
from glob import glob
from typing import List
from subprocess import Popen
from parseManifest import AndroidXMLDecompress
import xml.etree.ElementTree as ET
import zipfile
import shutil

FNULL = open(devnull, 'w')
'''
usage

python3 anubis.py '~/platform-tools/adb' '~/apk/d2/' 'b96742cb8a52add257e62d533f0ff84ac8fef98e4ca0ba4a1bbf502e3296897d.apk'
'''

'''
req: https://github.com/CyberSaxosTiGER/androidDump
'''

def clean():
    for i in glob('[0-9][0-9]**-out'):
        shutil.rmtree(i, ignore_errors=False, onerror=None)
    for i in glob('.*.apk_files'):
        shutil.rmtree(i, ignore_errors=False, onerror=None)
    shutil.rmtree('.android_tmp/', ignore_errors=False, onerror=None)


def get_packagename(apk: str) -> str:
    zip_ref = zipfile.ZipFile(apk, 'r')
    zip_ref.extractall('./.' + apk + '_files')
    zip_ref.close()

    parser = AndroidXMLDecompress()
    return str(ET.fromstring(parser.decompressXML(open('./.' + apk + '_files/AndroidManifest.xml', 'rb').read())).attrib['package'])


def grep(givenString, rootdir):
    for folder, dirs, files in walk(rootdir):
        for file in files:
            fullpath = path.join(folder, file)
            with open(fullpath, 'r', encoding="ISO-8859-1") as f:
                for line in f:
                    if givenString in line:
                        return str(fullpath)
    return None


def swap(i, i2, arr):
    i3 = arr[i]
    arr[i] = arr[i2]
    arr[i2] = i3


def solve(key: str, encoded: str) -> str:
    t = [i for i in range(256)]

    c = i2 = 0
    bArr = bytearray(key.encode("utf-8"))

    for i in range(256):
        i2 = (((i2 + t[i]) + bArr[i % len(bArr)]) + 256) % 256
        swap(i, i2, t)

    b = base64.b64decode(encoded).decode()

    barr3 = [(int(b[i], 16) << 4) + int(b[i+1], 16)
             for i in range(0, len(b), 2)]

    b = 0
    barr4 = []

    for i in range(len(barr3)):
        b = (b+1) % 256
        c = (c+t[b]) % 256
        swap(b, c, t)
        barr4.append(t[(t[b]+t[c]) % 256] ^ barr3[i])
    return ''.join([chr(x) for x in barr4])


def getkey(filename: str) -> List[str]:
    rt = []
    pivot = grep('https://twitter', str(filename + '-out/'))
    twitter = open(pivot).read().split('\n')[50].split('"')[1]

    rt.append(open(pivot).read().split('\n')[56].split('"')[1])
    response = requests.get(twitter)
    rt.append(twitter)
    soup = BeautifulSoup(response.text, "html.parser")
    tweets = soup.findAll('li', {"class": 'js-stream-item'})
    for tweet in tweets:
        if tweet.find('p', {"class": 'tweet-text'}):
            rt.append(str(tweet.find('p', {
                      "class": 'tweet-text'}).text.encode('utf8').strip()).split(">")[1].split("<")[0])
            break
    return rt


def adbRun(adb: str, packageName: str):
    if not path.isfile("androidDump.out"):
        print("Downloading androidDump.out ..")
        response = requests.get(
            "https://github.com/CyberSaxosTiGER/androidDump/releases/download/v1.0/androidDump.out")
        f = open("androidDump.out", "wb")
        f.write(response.content)
        f.close()
    p = Popen(adb + ' push androidDump.out /data/local/tmp',
              shell=True, stdout=FNULL, stderr=FNULL)
    p.wait()
    p = Popen(adb + ' shell \'cd /data/local/tmp && chmod +x androidDump.out && ./androidDump.out ' +
              packageName + "' &> /dev/null", shell=True, stdout=FNULL, stderr=FNULL)
    p.wait()
    p = Popen(adb + ' pull /data/local/tmp .android_tmp',
              shell=True, stdout=FNULL, stderr=FNULL)
    p.wait()


def adbInstall(adb: str, packageName: str):
    p = Popen(adb + ' install ' + packageName,
              shell=True, stdout=FNULL, stderr=FNULL)
    p.wait()


def adbUnsintall(adb: str, packageName: str):
    p = Popen(adb + ' uninstall ' + packageName,
              shell=True, stdout=FNULL, stderr=FNULL)
    p.wait()


def run(d2j: str, fileName: str):
    p = Popen(d2j + "d2j-dex2smali.sh .android_tmp/" + fileName +
              ".dex", shell=True, stdout=FNULL, stderr=FNULL)
    p.wait()


def dexExc() -> List[str]:
    bigFileList = glob('.android_tmp/[0-9][0-9][0-9][0-9]*')
    bigFileList.pop(0)
    filenames = [s for s in bigFileList if len(
        s) == max(len(s) for s in bigFileList)]
    for filename in filenames:
        with open(filename, 'rb') as f:
            content = f.read()
        hexoc = binascii.hexlify(content).split(b'6465780a')
        hexoc.pop(0)
        hexoc = b'6465780a' + b''.join(hexoc)
        dex = open(filename+".dex", "wb")
        dex.write(binascii.a2b_hex(hexoc[:int.from_bytes(
            binascii.a2b_hex(hexoc[:72][-8:]), byteorder='little')*2]))
        dex.close()
    return [filename.split('/')[len(filename.split('/')) - 1] for filename in filenames]


def main():
    adbPath = sys.argv[1]
    dex2jarPath = sys.argv[2]
    apk = sys.argv[3]
    packageName = get_packagename(apk)
    adbInstall(adbPath, apk)
    adbRun(adbPath, packageName)

    for dexName in dexExc():
        run(dex2jarPath, dexName)
        try:
            keys = getkey(dexName)
            print("twitter: ", keys[1])
            print("key:     ", keys[0])
            print("c2:      ", solve(keys[0], keys[2]))
            break
        except:
            pass
    adbUnsintall(adbPath, packageName)
    clean()


main()
