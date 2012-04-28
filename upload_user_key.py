from urllib import urlencode, urlopen
import sys

from Crypto.PublicKey import RSA

if __name__ == '__main__':
    privkeyf = open(sys.argv[1])
    pubkeyf = open(sys.argv[2])

    privkey = RSA.importKey(privkeyf.read())
    pubkey = RSA.importKey(pubkeyf.read())

    shibboleth = 'Rosie sent me'
    signature = privkey.sign(shibboleth, 'aksakqwmc899kq;ka;slci#@@TGCSAwoi9')[0]

    print signature

    data = urlencode({'username': 'zhemao', 'pubkey': pubkey.exportKey(),
                      'shibboleth': shibboleth, 'signature': str(signature)})

    f = urlopen('http://speakeasy-zhehao.rhcloud.com/pubkey', data=data)
    print f.read()

    privkeyf.close()
    pubkeyf.close()
