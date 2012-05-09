import os
import sys
from .auth import *
from .files import *
from ConfigParser import SafeConfigParser as ConfigParser
import json
import getpass
from .cryptfile import encrypt_file, decrypt_file
from Crypto import Random

DEFAULT_HOST = 'localhost'

def _load_cookies(username, privkey, host, password):
    cookiefname = os.path.expanduser('~/.bootlegger/cookiejar.json')
    if os.path.isfile(cookiefname):
        f = open(cookiefname)
        cookies = json.load(f)
        f.close()
        if cookies['username'] != username:
            cookies = authenticate(username, privkey, host, password)
            f = open(cookiefname, 'w')
            json.dump(cookies, f)
            f.close()
    else:
        cookies = authenticate(username, privkey, host, password)
        f = open(cookiefname, 'w')
        json.dump(cookies, f) 
        f.close()

    return dict([(str(key), str(val)) for (key, val) in cookies.items()])

def main():
    conf = ConfigParser()
    conf.read([os.path.expanduser('~/.bootlegger/bootlegger.conf')])

    if len(sys.argv) < 2:
        print "Usage: " + sys.argv[0] + " subcommand [args ... ]"
        exit(1)

    host = conf.get('speakeasy', 'host') or DEFAULT_HOST
    username = conf.get('speakeasy', 'username') or getpass.getuser()
    
    pubkeyfname = '~/.bootlegger/' + username + '_public.pem'
    privkeyfname = '~/.bootlegger/' + username + '_private.pem'

    pubkey = open(os.path.expanduser(pubkeyfname)).read()
    privkey = open(os.path.expanduser(privkeyfname)).read()
    
    if 'ENCRYPTED' in privkey:
        password = getpass.getpass('Password: ')
    else:
        password = ''

    cookies = _load_cookies(username, privkey, host, password)

    if sys.argv[1] == 'upload':
        for fname in sys.argv[2:]:
            upload(fname, pubkey, cookies, host)
    elif sys.argv[1] == 'download':
        for fname in sys.argv[2:]:
            download(fname, privkey, cookies, host, password)
    elif sys.argv[1] == 'addkey':
        add_pubkey(username, pubkey, privkey, host, password)
    elif sys.argv[1] == 'list':
        flist = list_files(cookies, host)

        for fname in flist:
            print fname

    elif sys.argv[1] == 'info':
        finfo = get_info(sys.argv[2], cookies, host)

        for key in finfo:
            print(key + ': ' + str(finfo[key]))

    elif sys.argv[1] == 'share':
        recipient = sys.argv[2]
        filenames = sys.argv[3:]

        for fname in filenames:
            share(fname, recipient, privkey, cookies, host, password)

    elif sys.argv[1] == 'versions':
        fname = sys.argv[2]

        dates = versions(fname, cookies, host)

        for d in dates:
            print(d)

    elif sys.argv[1] == 'delete':
        filenames = sys.argv[2:]

        for fname in filenames:
            delete(fname, cookies, host)

def blencrypt():
    if len(sys.argv) < 3:
        print 'Usage: ' + sys.argv[0] + ' infile keyfile'
        exit(1)

    infname = sys.argv[1]
    outfname = sys.argv[1] + '.bootleg'

    with open(sys.argv[2], 'rb') as f:
        key = f.read()

    encrypt_file(infname, outfname, key)

def bldecrypt():
    if len(sys.argv) < 3:
        print 'Usage: ' + sys.argv[0] + ' infile keyfile'
        exit(1)

    infname = sys.argv[1]
    outfname, suffix = os.path.splitext(infname)

    if suffix != '.bootleg':
        print 'Input must be a .bootleg file'
        exit(1)

    with open(sys.argv[2], 'rb') as f:
        key = f.read()

    decrypt_file(infname, outfname, key)

def blgenaeskey():
    if len(sys.argv) < 2:
        f = sys.stdout
    else:
        f = open(sys.argv[1], 'wb')

    key = Random.new().read(32)
    f.write(key)

    f.close()
