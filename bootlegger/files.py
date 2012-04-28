import requests
from Crypto.PublicKey import RSA
from Crypto import Random
import os
import io

DEFAULT_HOST = 'speakeasy-zhemao.rhcloud.com'

rng = Random.new().read

def upload(fname, pubkey, cookies, host=DEFAULT_HOST):
    f = open(fname)
    rsakey = RSA.importKey(pubkey)

    plain = f.read()
    cipher = rsakey.encrypt(plain, rng(384))

    url = 'http://' + host + '/file/upload'
    
    files = {os.path.basename(fname): io.StringIO(cipher)}

    r = requests.post(url, cookies=cookies, files=files)

    if r.status_code != 200:
        r.raise_for_status()

def download(fname, privkey, cookies, host=DEFAULT_HOST):
    url = 'http://' + host + '/file/download/' + fname

    r = requests.get(url, cookies=cookies)
    rsakey = RSA.importKey(privkey)
    plain = rsakey.decrypt(r.data)

    return plain

