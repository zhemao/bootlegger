import requests
from Crypto.PublicKey import RSA
from Crypto import Random

rng = Random.new().read

def get_pubkey(username, host):
    url = 'http://' + host + '/pubkey/' + username
    r = requests.get(url)

    if r.status_code != 200:
        r.raise_for_status()

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


