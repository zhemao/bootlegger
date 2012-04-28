import requests
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
import os
from cStringIO import StringIO
from base64 import b64encode, b64decode

DEFAULT_HOST = 'speakeasy-zhemao.rhcloud.com'

rng = Random.new().read

def upload(fname, pubkey, cookies, host=DEFAULT_HOST):
    f = open(fname)
    rsakey = RSA.importKey(pubkey)

    plain = f.read()
    
    if len(plain) % 16 != 0:
        padding = 16 - len(plain) % 16
        plain += '\0' * padding

    aes_key = rng(32)
    aes = AES.new(aes_key)
    cipher = aes.encrypt(plain)
    aes_key = rsakey.encrypt(aes_key, rng(384))[0]
    aes_key = unicode(b64encode(aes_key))

    url = 'http://' + host + '/file/upload'
    
    files = {'file': (os.path.basename(fname), StringIO(cipher))}
    headers = {'X-Symmetric-Key': str(aes_key)}
    print headers
    print cookies

    r = requests.post(url, cookies=cookies, files=files, headers=headers)

    if r.status_code != 200:
        r.raise_for_status()

def _strip_zeros(text):
    for i in range(len(text)-1, -1, -1):
        if text[i] != '\0':
            return text[:i+1]
    return ''

def download(fname, privkey, cookies, host=DEFAULT_HOST):
    url = 'http://' + host + '/file/download/' + fname

    r = requests.get(url, cookies=cookies)
    aes_key = b64decode(r.headers['X-Symmetric-Key'])
    rsakey = RSA.importKey(privkey)
    aes_key = rsakey.decrypt(aes_key)
    aes = AES.new(aes_key)
    plain = aes.decrypt(r.content)

    return _strip_zeros(plain)

