import os
import sys
from .auth import *
from .files import *
from ConfigParser import SafeConfigParser as ConfigParser
import json
import getpass

DEFAULT_HOST = 'localhost'

def _load_cookies(username, privkey, host, password):
    cookiefname = os.path.expanduser('~/.bootlegger/cookiejar.json')
    if os.path.isfile(cookiefname):
        f = open(cookiefname)
        cookies = json.load(f)
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
            raw = download(fname, privkey, cookies, host, password)
            f = open(fname, 'wb')
            f.write(raw)
            f.close()
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
