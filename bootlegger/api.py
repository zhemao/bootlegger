import requests
from Crypto.PublicKey import RSA
from Crypto import Random
import os
from base64 import b64encode, b64decode, b16encode
import json
from .cryptfile import encrypt_file, decrypt_file
import hashlib

rng = Random.new().read
DEFAULT_HOST = 'localhost'

def md5file(fname):
    f = open(fname, 'rb')
    cksum = hashlib.md5()

    for chunk in f:
        cksum.update(chunk)

    f.close()

    return cksum.hexdigest()

class SecurityException(BaseException):
    def __init__(self, msg):
        self.msg = msg
    def __str__(self):
        return self.msg
    def __repr__(self):
        return 'SecurityException: ' + self.msg

class BootLegger(object):
    """The base class for interacting with speakeasy"""
    def __init__(self, username, pubkey, privkey, 
                 host = DEFAULT_HOST, password = '', auth = True):
        """username is the username of the speakeasy user
           pubkey is the user's public key as a string
           privkey is the user's private key as a string
           host is the host that speakeasy is running on (default is localhost)
           password is the password for the private key (default to blank / no password)
           auth determines whether to connect and authenticate immediately (default to true)"""
        self.username = username
        self.password = password
        self.host = host

        self.pubkey = pubkey
        self.privkey = privkey

        if auth:
            self.authenticate()
   
    def authenticate(self):
        """Authenticate to speakeasy. You do not need to call this yourself
           if you set auth = True in the constructor"""
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
        """Encrypt and upload the file given by fname to the server.
           fname should be the full path to the file.
           You can set the optional argument rname to give the file a 
           different name on the server"""
        rsakey = RSA.importKey(self.pubkey)
        
        aes_key = rng(32)
        tempname = '/var/tmp/' + b16encode(rng(16)) + '.bootleg'
        encrypt_file(fname, tempname, aes_key)
        aes_key = rsakey.encrypt(aes_key, rng(384))[0]
        aes_key = b64encode(aes_key)
        
        cksum = md5file(fname)

        url = 'http://' + self.host + '/file/upload'
        
        cryptf = open(tempname)

        if not rname:
            rname = os.path.basename(fname)

        files = {'file': (rname, cryptf)}
        headers = {'Symmetric-Key': str(aes_key),
                   'Plaintext-MD5': cksum}

        r = requests.post(url, cookies=self.cookies, files=files, headers=headers)

        cryptf.close()

        if r.status_code != 200:
            r.raise_for_status()

        os.remove(tempname)

    def download(self, fname, lname = None):
        """Download and decrypt the file given by fname from the server.
           By default it creates the file in the current directory with 
           the same name as on the server. To give the downloaded file a 
           different name or download it to a different location, set the
           lname parameter to where you want the file downloaded."""
        url = 'http://' + self.host + '/file/download/' + fname
        tempname = '/var/tmp/' + b16encode(rng(16)) + '.bootleg'
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

        os.remove(tempname)

    def list_files(self, pattern = None):
        """Get a list of the names of the files stored on the server.
           If the optional argument pattern is given, the method will
           only list files matching the pattern. 
           Pattern should by a unix-style file glob."""
        url = 'http://' + self.host + '/file/list'

        if pattern:
            url += '/' + pattern
        
        r = requests.get(url, cookies=self.cookies)

        if r.status_code != 200:
            r.raise_for_status()

        resp = json.loads(r.text)

        return resp['files']

    def get_info(self, fname):
        """Get more detailed information about the file called fname
           from the server."""
        url = 'http://' + self.host + '/file/info/' + fname

        r = requests.get(url, cookies=self.cookies)

        if r.status_code != 200:
            r.raise_for_status()

        resp = json.loads(r.text)

        return resp['fileinfo']

    def share(self, fname, recipient):
        """Share a file called fname stored on the server with the recipient"""
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
        """Get the dates of previous modifications to the file."""
        url = 'http://' + self.host + '/file/versions/' + fname

        r = requests.get(url, cookies=self.cookies)

        if r.status_code != 200:
            r.raise_for_status()

        resp = json.loads(r.text)

        return resp['dates']

    def delete(self, fname):
        """Delete a file from the server."""
        url = 'http://' + self.host + '/file/delete/' + fname

        r = requests.post(url, cookies=self.cookies)

        if r.status_code != 200:
            r.raise_for_status()

    def get_pubkey(self, username):
        """Get the public key of a user.
           Takes the user's username as an argument.
           Returns the public key as a string."""
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
        """Add a public key to the server."""
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


