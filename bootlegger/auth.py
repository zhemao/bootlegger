import requests
from Crypto.PublicKey import RSA
from Crypto import Random

DEFAULT_HOST = 'speakeasy-zhemao.rhcloud.com'

rng = Random.new().read

def get_pubkey(username, host=DEFAULT_HOST):
    url = 'http://' + host + '/pubkey/' + username
    r = requests.get(url)

    if r.status_code != 200:
        r.raise_for_status()

    return r.text

def authenticate(username, privkey, host=DEFAULT_HOST):
    url = 'http://' + host + '/authenticate'
    rsakey = RSA.importKey(privkey)
    shibboleth = 'Rosie sent me'
    signature, _ = rsakey.sign(shibboleth, rng(284))
    data = {'username': username, 
            'shibboleth': shibboleth, 
            'signature': str(signature)}

    r = requests.post(url, data=data)
    
    if r.status_code != 200:
        r.raise_for_status()

    return r.cookies

