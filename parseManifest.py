class AndroidXMLDecompress():
    endDocTag = 0x00100101
    startTag = 0x00100102
    endTag = 0x00100103

    def decompressXML(self, xml: bytearray) -> str:

        finalXml = str()

        numbStrings = self.LEW(xml, 4*4)

        sitOff = 0x24
        stOff = sitOff + numbStrings * 4
        xmlTagOff = self.LEW(xml, 3 * 4)
        for i in range(xmlTagOff, len(xml) - 4, 4):
            if self.LEW(xml, i) == self.startTag:
                xmlTagOff = i
                break

        off = xmlTagOff

        while (off < len(xml)):
            tag0 = self.LEW(xml, off)
            nameSi = self.LEW(xml, off + 5 * 4)

            if tag0 == self.startTag:
                numbAttrs = self.LEW(xml, off + 7*4)
                off += 9*4
                name = self.compXmlString(xml, sitOff, stOff, nameSi)
                sb = str()
                for i in range(numbAttrs):
                    attrNameSi      = self.LEW(xml, off +   1 * 4 )
                    attrValueSi     = self.LEW(xml, off +   2 * 4 )
                    attrResId       = self.LEW(xml, off +   4 * 4 )

                    off += 5*4

                    attrName = self.compXmlString(xml,sitOff,stOff,attrNameSi)
                    attrValue = str()
                    if attrValueSi is not -1:
                        attrValue = self.compXmlString(xml, sitOff, stOff, attrValueSi)
                    else:
                        attrValue = "resourceID " + hex(attrResId)
                    sb += " " + attrName + "=\"" + attrValue + "\""
                finalXml += "<" + name + sb + ">"
            elif tag0 == self.endTag:
                off += 6*4
                name = self.compXmlString(xml, sitOff, stOff, nameSi)
                finalXml += "</" + name + ">"
            elif tag0 == self.endDocTag:
                        break
            else:
                break
        return finalXml


    def compXmlString(self, xml: bytearray, sitOff: int, stOff: int, strInd: int) -> str:
        if strInd < 0:
            return None
        strOff = stOff + self.LEW(xml, sitOff + strInd*4)
        return self.compXmlStringAt(xml, strOff)

    def compXmlStringAt(self, arr: bytearray, strOff: bytearray) -> str:
        strlen = arr[strOff + 1] << 8 & 0xff00 | arr[strOff] & 0xff
        chars = bytearray()
        for i in range(strlen):
            chars.append(arr[strOff + 2 + i*2])
        return chars.decode("utf-8")

    def LEW(self, arr: bytearray, off: int) -> int:
        c = arr[off + 3] << 24 & 0xff000000 | arr[off + 2] << 16 & 0xff0000 | arr[off + 1] << 8 & 0xff00 | arr[off] & 0xFF
        if c < -2147483648 or c > 2147483647:
            return int(-1)
        return arr[off + 3] << 24 & 0xff000000 | arr[off + 2] << 16 & 0xff0000 | arr[off + 1] << 8 & 0xff00 | arr[off] & 0xFF