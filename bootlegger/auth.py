import requests
from Crypto.PublicKey import RSA
from Crypto import Random
import os

rng = Random.new().read

class SecurityException(BaseException):
    def __init__(self, msg):
        self.msg = msg
    def __str__(self):
        return self.msg
    def __repr__(self):
        return 'SecurityException: ' + self.msg

def get_pubkey(username, host):
    fname = os.path.expanduser('~/.bootlegger/' + username + '_public.pem')

    if os.path.isfile(fname):
        f = open(fname)
        s = f.read()
        f.close()
        return s

    url = 'http://' + host + '/pubkey/' + username
    r = requests.get(url)

    if r.status_code != 200:
        r.raise_for_status()

    f = open(fname, 'w')
    f.write(r.text)
    f.close()

    return r.text

def authenticate(username, privkey, host, password):
    url = 'http://' + host + '/authenticate'
    rsakey = RSA.importKey(privkey, password)
    shibboleth = 'Rosie sent me'
    signature = rsakey.sign(shibboleth, rng(384))[0]
    data = {'username': username, 
            'shibboleth': shibboleth, 
            'signature': str(signature)}

    r = requests.post(url, data=data)
    
    if r.status_code != 200:
        r.raise_for_status()

    servkey = get_pubkey('server', host)
    rsakey = RSA.importKey(servkey)
    servsig = int(r.cookies['signature'])

    if not rsakey.verify(username, (servsig,)):
        raise SecurityException('Could not verify server signature') 

    return r.cookies

def add_pubkey(username, pubkey, privkey, host, password):
    rsakey = RSA.importKey(privkey, password)
    shibboleth = 'Rosie sent me'
    signature = rsakey.sign(shibboleth, rng(384))[0]
    data = {'username': username, 
            'shibboleth': shibboleth, 
            'signature': str(signature),
            'pubkey': pubkey}

    url = 'http://' + host + '/pubkey/add'
    
    r = requests.post(url, data=data)
    
    if r.status_code != 200:
        r.raise_for_status()

    return r.cookies


