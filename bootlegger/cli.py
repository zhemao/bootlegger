import os
import sys
from .auth import *
from .files import *
from ConfigParser import SafeConfigParser as ConfigParser
import json

def main():
    conf = ConfigParser()
    conf.read([os.path.expanduser('~/.bootlegger/bootlegger.conf')])

    if len(sys.argv) < 1:
        print "Usage: " + sys.argv[0] + " subcommand [args ... ]"
        exit(1)

    host = conf.get('speakeasy', 'host')
    username = conf.get('speakeasy', 'username')
    pubkey = open(os.path.expanduser('~/.bootlegger/user_public.pem')).read()
    privkey = open(os.path.expanduser('~/.bootlegger/user_private.pem')).read()

    cookiefname = os.path.expanduser('~/.bootlegger/cookiejar.json')
    if os.path.isfile(cookiefname):
        f = open(cookiefname)
        cookies = json.load(f)
        f.close()
    else:
        cookies = authenticate(username, privkey, host)
        f = open(cookiefname, 'w')
        json.dump(cookies, f) 
        f.close()

    if sys.argv[1] == 'upload':
        fname = sys.argv[2]
        upload(fname, pubkey, cookies, host)
    elif sys.argv[1] == 'download':
        fname = sys.argv[2]
        raw = download(fname, privkey, cookies, host)
        f = open(fname, 'wb')
        f.write(raw)
        f.close()
    
