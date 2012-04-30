import requests
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
import os
from cStringIO import StringIO
from base64 import b64encode, b64decode
import json
from auth import get_pubkey
from .cryptfile import encrypt_file, decrypt_file

rng = Random.new().read

def upload(fname, pubkey, cookies, host):
    rsakey = RSA.importKey(pubkey)
    
    aes_key = rng(32)
    tempname = '/tmp/' + b64encode(rng(16)) + '.bootleg'
    encrypt_file(fname, tempname, aes_key)
    aes_key = rsakey.encrypt(aes_key, rng(384))[0]
    aes_key = b64encode(aes_key)

    url = 'http://' + host + '/file/upload'
    
    cryptf = open(tempname)

    files = {'file': (os.path.basename(fname), cryptf)}
    headers = {'X-Symmetric-Key': str(aes_key)}

    r = requests.post(url, cookies=cookies, files=files, headers=headers)

    cryptf.close()

    if r.status_code != 200:
        r.raise_for_status()

def download(fname, privkey, cookies, host, password):
    url = 'http://' + host + '/file/download/' + fname
    tempname = '/tmp/' + b64encode(rng(16)) + '.bootleg'
    r = requests.get(url, cookies=cookies)

    if r.status_code != 200:
        r.raise_for_status()

    with open(tempname, 'wb') as tempf:
        for chunk in r.iter_content():
            tempf.write(chunk)
    
    aes_key = b64decode(r.headers['X-Symmetric-Key'])
    rsakey = RSA.importKey(privkey, password)
    aes_key = rsakey.decrypt(aes_key)

    decrypt_file(tempname, fname, aes_key)

def list_files(cookies, host):
    url = 'http://' + host + '/file/list'
    
    r = requests.get(url, cookies=cookies)

    if r.status_code != 200:
        r.raise_for_status()

    resp = json.loads(r.text)

    return resp['files']

def get_info(fname, cookies, host):
    url = 'http://' + host + '/file/info/' + fname

    r = requests.get(url, cookies=cookies)

    if r.status_code != 200:
        r.raise_for_status()

    resp = json.loads(r.text)

    return resp['fileinfo']

def share(fname, recipient, privkey, cookies, host, password):
    finfo = get_info(fname, cookies, host)
    
    rsakey = RSA.importKey(privkey, password)
    aes_key = rsakey.decrypt(b64decode(finfo['aes_key']))
    
    pubkey = get_pubkey(recipient, host)
    rsakey = RSA.importKey(pubkey)
    
    aes_key = rsakey.encrypt(aes_key, rng(384))[0]
    aes_key = unicode(b64encode(aes_key))

    headers = {'X-Symmetric-Key': aes_key}
    data = {'recipient': recipient, 'filename': fname}

    url = 'http://' + host + '/file/share'

    r = requests.post(url, headers=headers, data=data, cookies=cookies)

    if r.status_code != 200:
        r.raise_for_status()

def versions(fname, cookies, host):
    url = 'http://' + host + '/file/versions/' + fname

    r = requests.get(url, cookies=cookies)

    if r.status_code != 200:
        r.raise_for_status()

    resp = json.loads(r.text)

    return resp['dates']

def delete(fname, cookies, host):
    url = 'http://' + host + '/file/delete/' + fname

    r = requests.post(url, cookies=cookies)

    if r.status_code != 200:
        r.raise_for_status()
