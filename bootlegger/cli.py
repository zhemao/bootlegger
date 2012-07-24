import os
import sys
from .api import BootLegger
from ConfigParser import SafeConfigParser as ConfigParser
import json
import getpass
from .cryptfile import encrypt_file, decrypt_file
from Crypto import Random
from argparse import ArgumentParser

DEFAULT_HOST = 'localhost'

def expand_file_list(bl, file_list):
    new_file_list = []

    for filename in file_list:
        if '*' in filename:
            new_file_list.extend(bl.list_files(filename))
        else:
            new_file_list.append(filename)

    return new_file_list

def perform_action(host, username, password, pubkey, privkey, args):
    if args.subcommand == 'addkey':
        bl = BootLegger(username, pubkey, privkey, host, password, False)
        bl.add_pubkey()
        sys.exit(0)
       
    bl = BootLegger(username, pubkey, privkey, host, password) 

    if args.subcommand == 'upload':
        if len(args.subargs) == 0:
            return "no files to upload"
        for fname in args.subargs:
            if args.prefix:
                rname = args.prefix + '_' + os.path.basename(fname)
            else: rname = os.path.basename(fname)
            
            bl.upload(fname, rname)
    
    elif args.subcommand == 'download':
        if len(args.subargs) == 0:
            return "no files to download"

        file_list = expand_file_list(bl, args.subargs)
        
        for fname in file_list:
            lname = fname
            
            if args.prefix:
                fname = args.prefix + '_' + fname
            
            if args.directory:
                lname = os.path.join(args.directory, lname)

            bl.download(fname, lname)
    
    elif args.subcommand == 'list':
        if len(args.subargs) > 0:
            flist = bl.list_files(args.subargs[0])
        else:
            flist = bl.list_files()

        for fname in flist:
            print fname

    elif args.subcommand == 'info':
        if len(args.subargs) == 0:
            return "Must provide filename"

        finfo = bl.get_info(args.subargs[0])

        for key in finfo:
            print(key + ': ' + str(finfo[key]))

    elif args.subcommand == 'share':
        if len(args.subargs) < 2:
            return "Must provide recipient and filenames"
        recipient = args.subargs[0]
        filenames = expand_file_list(bl, args.subargs[1:])

        for fname in filenames:
            bl.share(fname, recipient)

    elif args.subcommand == 'versions':
        if len(args.subargs) == 0:
            return "must provide filename"
        fname = args.subargs[0]

        dates = bl.versions(fname)

        for d in dates:
            print(d)

    elif args.subcommand == 'delete':
        if len(args.subargs) == 0:
            return "must provide filenames"

        file_list = expand_file_list(bl, args.subargs)
        
        for fname in file_list:
            bl.delete(fname)

def main():
    conf = ConfigParser()
    conf.read([os.path.expanduser('~/.bootlegger/bootlegger.conf')])

    if len(sys.argv) < 2:
        print "Usage: " + sys.argv[0] + " subcommand [args ... ]"
        exit(1)

    host = conf.get('speakeasy', 'host') or DEFAULT_HOST
    username = conf.get('speakeasy', 'username') or getpass.getuser()
    
    parser = ArgumentParser(description='interact with speakeasy')
    parser.add_argument('subcommand', help='one of list, upload, download, share, addkey, versions')
    parser.add_argument('subargs', nargs='*', help='arguments for subcommand')
    parser.add_argument('--host', dest='host',
                        help='the host on which speakeasy is running')
    parser.add_argument('--username', dest='username',
                        help='username to use when authenticating')
    parser.add_argument('-p', '--prefix', dest='prefix',
                        help='the prefix you wish to use for all uploaded files')
    parser.add_argument('-d', '--directory', dest='directory',
                        help='the directory to which files should be downloaded')

    args = parser.parse_args()

    if args.username: username = args.username
    if args.host: host = args.host

    pubkeyfname = '~/.bootlegger/' + username + '_public.pem'
    privkeyfname = '~/.bootlegger/' + username + '_private.pem'

    pubkey = open(os.path.expanduser(pubkeyfname)).read()
    privkey = open(os.path.expanduser(privkeyfname)).read()
    
    if 'ENCRYPTED' in privkey:
        password = getpass.getpass('Password: ')
    else:
        password = ''

    errmsg = perform_action(host, username, password, pubkey, privkey, args)

    if errmsg:
        print(errmsg)
        sys.exit(1)

    
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
