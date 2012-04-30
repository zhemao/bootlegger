from Crypto.Cipher import AES
import struct

CHUNK_SIZE = 1024

class AESFile:
    def _read_all(self):
        chunk = self._read_chunk(CHUNK_SIZE)
        whole = ''

        while chunk:
            whole += chunk
            chunk = self._read_chunk(CHUNK_SIZE)

        return whole

    def read(self, n = -1):
        if n < 0:
            return self._read_all()
        else:
            return self._read_chunk(n)

    def __iter__(self):
        chunk = self._read_chunk(CHUNK_SIZE)
        while chunk:
            yield chunk
            chunk = self._read_chunk(CHUNK_SIZE)

class CryptFile(AESFile):
    def __init__(self, f, key):
        self.file = f
        self.aes = AES.new(key)

    def _read_chunk(self, n):
        filen = n - struct.calcsize('!i')
        if filen % 16 != 0:
            filen = filen - (filen % 16)
        
        chunk = self.file.read(filen)
        realn = len(chunk)

        if realn == 0:
            return ''

        if realn % 16 != 0:
            chunk += '\0' * (16 - realn % 16)

        head = struct.pack('!i', realn)

        return head + self.aes.encrypt(chunk)

    
    
    def close(self):
        self.file.close()

class DecryptFile(AESFile):
    def __init__(self, f, key):
        self.file = f
        self.aes = AES.new(key)
        self.temp = ''

    def _read_chunk(self, n):
        if len(self.temp) >= n:
            chunk = self.temp[:n]
            self.temp = self.temp[n:]
            return chunk

        headn = struct.calcsize('!i')
        head = self.file.read(headn)
        realn, = struct.unpack(head)
        
        filen = realn + (16 - realn % 16)
        chunk = self.file.read(filen)

        while len(chunk) < filen:
            chunk += self.file.read(filen - len(chunk))

        plain = self.temp + self.aes.decrypt(chunk)[:realn]

        if n < len(plain):
            self.temp = plain[n:]
            return plain[:n]

        self.temp = ''
        return plain


