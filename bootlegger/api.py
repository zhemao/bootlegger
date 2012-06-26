import requests
from Crypto.PublicKey import RSA
from Crypto import Random
import os
from base64 import b64encode, b64decode
import json
from .cryptfile import encrypt_file, decrypt_file

rng = Random.new().read
DEFAULT_HOST = 'localhost'

class SecurityException(BaseException):
    def __init__(self, msg):
        self.msg = msg
    def __str__(self):
        return self.msg
    def __repr__(self):
        return 'SecurityException: ' + self.msg

def hexencode(s):
    return ''.join([hex(ord(c)).replace('0x', '') for c in s])

class BootLegger(object):
    def __init__(self, username, pubkey, privkey, 
                 host = DEFAULT_HOST, password = '', auth = True):
        self.username = username
        self.password = password
        self.host = host

        self.pubkey = pubkey
        self.privkey = privkey

        if auth:
            self.authenticate()
   
    def authenticate(self):
        cookiefname = os.path.expanduser('~/.bootlegger/cookiejar.json')
        write_cookies = True

        if os.path.isfile(cookiefname):
            f = open(cookiefname)
            cookies = json.load(f)
            f.close()
            if cookies['username'] != self.username:
                cookies = self._real_auth()
            else:
                write_cookies = False
        else:
            cookies = self._real_auth()

        self.cookies = dict([(str(key), str(val)) for (key, val) in cookies.items()])

        if write_cookies:
            f = open(cookiefname, 'w')
            json.dump(self.cookies, f) 
            f.close()
       
    def upload(self, fname, rname = None):
        rsakey = RSA.importKey(self.pubkey)
        
        aes_key = rng(32)
        tempname = '/tmp/' + hexencode(rng(16)) + '.bootleg'
        encrypt_file(fname, tempname, aes_key)
        aes_key = rsakey.encrypt(aes_key, rng(384))[0]
        aes_key = b64encode(aes_key)

        url = 'http://' + self.host + '/file/upload'
        
        cryptf = open(tempname)

        if not rname:
            rname = os.path.basename(fname)

        files = {'file': (rname, cryptf)}
        headers = {'Symmetric-Key': str(aes_key)}

        r = requests.post(url, cookies=self.cookies, files=files, headers=headers)

        cryptf.close()

        if r.status_code != 200:
            r.raise_for_status()

    def download(self, fname, lname = None):
        url = 'http://' + self.host + '/file/download/' + fname
        tempname = '/tmp/' + hexencode(rng(16)) + '.bootleg'
        r = requests.get(url, cookies=self.cookies)

        if not lname:
            lname = fname

        if r.status_code != 200:
            r.raise_for_status()

        with open(tempname, 'wb') as tempf:
            for chunk in r.iter_content():
                tempf.write(chunk)
        
        aes_key = b64decode(r.headers['Symmetric-Key'])
        rsakey = RSA.importKey(self.privkey, self.password)
        aes_key = rsakey.decrypt(aes_key)

        decrypt_file(tempname, lname, aes_key)

    def list_files(self, pattern = None):
        url = 'http://' + self.host + '/file/list'

        if pattern:
            url += '/' + pattern
        
        r = requests.get(url, cookies=self.cookies)

        if r.status_code != 200:
            r.raise_for_status()

        resp = json.loads(r.text)

        return resp['files']

    def get_info(self, fname):
        url = 'http://' + self.host + '/file/info/' + fname

        r = requests.get(url, cookies=self.cookies)

        if r.status_code != 200:
            r.raise_for_status()

        resp = json.loads(r.text)

        return resp['fileinfo']

    def share(self, fname, recipient):
        finfo = self.get_info(fname)
        
        rsakey = RSA.importKey(self.privkey, self.password)
        aes_key = rsakey.decrypt(b64decode(finfo['aes_key']))
        
        pubkey = self.get_pubkey(recipient)
        rsakey = RSA.importKey(pubkey)
        
        aes_key = rsakey.encrypt(aes_key, rng(384))[0]
        aes_key = b64encode(aes_key)

        headers = {'Symmetric-Key': aes_key}
        data = {'recipient': recipient, 'filename': fname}

        url = 'http://' + self.host + '/file/share'

        r = requests.post(url, headers=headers, data=data, cookies=self.cookies)

        if r.status_code != 200:
            r.raise_for_status()

    def versions(self, fname):
        url = 'http://' + self.host + '/file/versions/' + fname

        r = requests.get(url, cookies=self.cookies)

        if r.status_code != 200:
            r.raise_for_status()

        resp = json.loads(r.text)

        return resp['dates']

    def delete(self, fname):
        url = 'http://' + self.host + '/file/delete/' + fname

        r = requests.post(url, cookies=self.cookies)

        if r.status_code != 200:
            r.raise_for_status()

    def get_pubkey(self, username):
        fname = os.path.expanduser('~/.bootlegger/' + username + '_public.pem')

        if os.path.isfile(fname):
            f = open(fname)
            s = f.read()
            f.close()
            return s

        url = 'http://' + self.host + '/pubkey/' + username
        r = requests.get(url)

        if r.status_code != 200:
            r.raise_for_status()

        f = open(fname, 'w')
        f.write(r.text)
        f.close()

        return r.text

    def _real_auth(self):
        url = 'http://' + self.host + '/authenticate'
        rsakey = RSA.importKey(self.privkey, self.password)
        shibboleth = 'Mom sent me'
        signature = rsakey.sign(shibboleth, rng(384))[0]
        data = {'username': self.username, 
                'shibboleth': shibboleth, 
                'signature': str(signature)}

        r = requests.post(url, data=data)
        
        if r.status_code != 200:
            r.raise_for_status()

        if not r.cookies['signature']:
            raise SecurityException('Server did not return cookie.')

        servkey = self.get_pubkey('server')
        rsakey = RSA.importKey(servkey)
        servsig = int(r.cookies['signature'])

        if not rsakey.verify(self.username, (servsig,)):
            raise SecurityException('Could not verify server signature') 

        return r.cookies

    def add_pubkey(self):
        rsakey = RSA.importKey(self.privkey, self.password)
        shibboleth = 'Rosie sent me'
        signature = rsakey.sign(shibboleth, rng(384))[0]
        data = {'username': self.username, 
                'shibboleth': shibboleth, 
                'signature': str(signature),
                'pubkey': self.pubkey}

        url = 'http://' + self.host + '/pubkey/add'
        
        r = requests.post(url, data=data)
        
        if r.status_code != 200:
            r.raise_for_status()

        if not r.cookies['signature']:
            raise SecurityException('Server did not return cookie')
        
        servkey = self.get_pubkey('server')
        rsakey = RSA.importKey(servkey)
        servsig = int(r.cookies['signature'])

        if not rsakey.verify(self.username, (servsig,)):
            raise SecurityException('Could not verify server signature')

        return r.cookies


