
from blowfish import Blowfish
import os,struct

def xor(x,y):
    return "".join([chr(ord(a)^ord(b)) for a,b in zip(x,y)])

class SDSEncrypt(Blowfish):

    def encryptCBC(self,iv,data):
        if len(iv) < 8:
            iv = iv + ('\x00' * (8 - len(iv)))
        if len(iv) > 8:
            iv = iv[:8]
        hdr = struct.pack('<i',len(data)) + iv 
        if len(data) % 8:
            data += ('\x00' * (8 - (len(data) % 8)))
        enc = ""
        while data:
            z = self.encrypt(xor(iv,data[:8]))
            iv = z
            data = data[8:]
            enc += z
        return hdr + enc

    def decryptCBC(self,data):
        _len = struct.unpack('<i',data[:4])[0]
        data = data[4:]
        raw = ""
        while len(data) > 8:
            x = xor(self.decrypt(data[-8:]),data[-16:-8])
            data = data[:-8]
            raw = x + raw
        return raw[:_len]

if __name__ == '__main__':
    import optparse,getpass,sys
    parser = optparse.OptionParser(usage="Usage: %prog [options]")
    parser.add_option("--encrypt",action="store_true", dest="encrypt", default=True)
    parser.add_option("--decrypt",action="store_false", dest="encrypt")
    parser.add_option("--key")
    parser.add_option("--hex",action="store_true")
    options,args = parser.parse_args()

    if options.key is None:
        options.key = getpass.getpass("Key:")

    z = SDSEncrypt(options.key)

    if options.encrypt:
        data = sys.stdin.read()
        iv = os.urandom(8)
        out = z.encryptCBC(iv,data)
        if options.hex:
            sys.stdout.write(out.encode('hex'))
        else:
            sys.stdout.write(out)
    else:
        if options.hex:
            data = sys.stdin.read().decode('hex')
        else:
            data = sys.stdin.read()
        out = z.decryptCBC(data)
        sys.stdout.write(out)

