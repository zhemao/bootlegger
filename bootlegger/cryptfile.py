from Crypto.Cipher import AES
import struct

CHUNK_SIZE = 32768

def encrypt_chunk(f, aes):
    chunk = f.read(CHUNK_SIZE)
    realn = len(chunk)

    if realn == 0:
        return ''

    if realn % 16 != 0:
        padding = 16 - (realn % 16)
        chunk += ' ' * padding

    head = struct.pack('!H', realn)
    
    return head + aes.encrypt(chunk)

def decrypt_chunk(f, aes):
    headn = struct.calcsize('!H')
    head = f.read(headn)

    if len(head) == 0:
        return ''

    realn, = struct.unpack('!H', head)

    if realn % 16 != 0:
        n = realn + (16 - (realn % 16))
    else:
        n = realn

    chunk = f.read(n)
    plain = aes.decrypt(chunk)

    return plain[:realn]

def transform_file(infname, outfname, key, chunk_func):
    inf = open(infname, 'rb')
    outf = open(outfname, 'wb')
    
    aes = AES.new(key)
    chunk = chunk_func(inf, aes)

    while chunk:
        outf.write(chunk)
        chunk = chunk_func(inf, aes)

    inf.close()
    outf.close()

def encrypt_file(infname, outfname, key):
    transform_file(infname, outfname, key, encrypt_chunk)

def decrypt_file(infname, outfname, key):
    transform_file(infname, outfname, key, decrypt_chunk)

