import os
import sys
from .api import BootLegger
from ConfigParser import SafeConfigParser as ConfigParser
import json
import getpass
from .cryptfile import encrypt_file, decrypt_file
from Crypto import Random

DEFAULT_HOST = 'localhost'

def perform_action(bl):
    if sys.argv[1] == 'upload':
        for fname in sys.argv[2:]:
            bl.upload(fname)
    
    elif sys.argv[1] == 'download':
        for fname in sys.argv[2:]:
            bl.download(fname)
    
    elif sys.argv[1] == 'list':
        if len(sys.argv) > 2:
            flist = bl.list_files(sys.argv[2])
        else:
            flist = bl.list_files()

        for fname in flist:
            print fname

    elif sys.argv[1] == 'info':
        finfo = bl.get_info(sys.argv[2])

        for key in finfo:
            print(key + ': ' + str(finfo[key]))

    elif sys.argv[1] == 'share':
        recipient = sys.argv[2]
        filenames = sys.argv[3:]

        for fname in filenames:
            bl.share(fname, recipient)

    elif sys.argv[1] == 'versions':
        fname = sys.argv[2]

        dates = bl.versions(fname)

        for d in dates:
            print(d)

    elif sys.argv[1] == 'delete':
        filenames = sys.argv[2:]

        for fname in filenames:
            bl.delete(fname)

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

    if sys.argv[1] == 'addkey':
        bl = BootLegger(username, pubkey, privkey, host, password, False)
        bl.add_pubkey()
        sys.exit(0)
        
    bl = BootLegger(username, pubkey, privkey, host, password) 

    perform_action(bl)    

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
