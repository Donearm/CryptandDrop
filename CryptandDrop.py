#!/usr/bin/env python
# -*- coding: utf-8 -*-
###############################################################################
# Copyright (c) 2011-2020, Gianluca Fiore
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Lesser General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
###############################################################################

__author__ = "Gianluca Fiore"
__license__ = "GPL"
__version__ = "0.1"
__date__ = "20111108"
__email__ = "forod.g@gmail.com"
__status__ = "alpha"

import sys
import argparse
import getpass
import base64
import fnmatch
from os import urandom, getcwd
import os.path
from configparser import SafeConfigParser, NoOptionError, NoSectionError
from dropbox import client, rest, session
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Hash import HMAC
import json

CURRENTDIR = os.path.dirname(__file__) + '/'

APP_FOLDER = 'Crypted'
ACCESS_TYPE = 'app_folder'

BLOCK_SIZE = 16
SIG_SIZE = SHA256.digest_size

class AuthenticationError(Exception):
    pass


def argument_parser():
    """CLI argument parser"""
    cli_parser = argparse.ArgumentParser()
    
    # either encrypt or decrypt, and at least one of them
    exclusive_group = cli_parser.add_mutually_exclusive_group(required=False)
    exclusive_group.add_argument("-c", "--encrypt",
            action="store_true",
            help="activate encryption mode",
            dest="encrypt")
    exclusive_group.add_argument("-d", "--decrypt",
            action="store_true",
            help="activate decryption mode",
            dest="decrypt")
    cli_parser.add_argument("-s", "--single-pass",
            action="store_true",
            help="use a single password for each file to encrypt/decrypt",
            dest="singlepass")
    cli_parser.add_argument("-r", "--remove",
            action="store_true",
            help="remove files matching the given pattern",
            dest="remove")
    cli_parser.add_argument("-f", "--config-file",
            action="store",
            help="use an alternative location for the config file",
            dest="configfile")
    cli_parser.add_argument(action="store",
            help="Files or files' patterns to act upon",
            nargs='*',
            dest="filelist")
    options = cli_parser.parse_args()
    return options, cli_parser


def import_config(configfile=""):
    """Import config file variables"""
    parser = SafeConfigParser(allow_no_value=True)
    if configfile:
        file_locations = [os.path.realpath(configfile)]
    else:
        file_locations = ['cryptanddrop.conf', os.path.expanduser('~/.cryptanddrop.conf')]

    try:
        parser.read(file_locations)
    except ParsingError as e:
        # the config file hasn't been found or it couldn't be parsed
        config_error()

    try:
        app_key = base64.b64decode(parser.get('auth', 'APP_KEY'))
        app_secret = base64.b64decode(parser.get('auth', 'APP_SECRET'))
    except NoSectionError as e:
        # the config file hasn't been found then
        config_error()

    try:
        access_token = parser.get('auth', 'ACCESS_TOKEN')
    except NoOptionError:
        # we lack an access token, let's request one then
        sess, access_token = connect_app_to_account(app_key, app_secret, ACCESS_TYPE)
        parser.set('auth', 'ACCESS_TOKEN', str(access_token))
        with open(filepath, 'w') as f:
            parser.write(f)

    dropbox_dir = parser.get('config', 'DROPBOX_DIR')

    return app_key, app_secret, access_token, dropbox_dir


def config_error():
    """Print message error on config file parsing errors"""
    print("No cryptanddrop.conf in current or home directory, exiting...")
    sys.exit(1)


def ask_password(filename, decrypting=False, onepassforall=False):
    """Ask the user for a password for the encrypted files"""
    if decrypting:
        if onepassforall:
            pwd = getpass.getpass("Insert the password for all files: ")
        else:
            pwd = getpass.getpass("Insert the password to decrypt %s: " % filename)
    else:
        if onepassforall:
            pwd = getpass.getpass("Please insert a password for the files: ")
        else:
            pwd = getpass.getpass("Please insert a password for %s: " % filename)

    if isinstance(pwd, str):
        return pwd
    else:
        raise TypeError
        sys.exit(1)


def split_token(tkn):
    """Split, twice, an access and access secret token string as returned by obtain_access_token
    returning only the tokens"""
    access_scrt, access = tkn.split('&')
    
    return access_scrt.split('=')[1], access.split('=')[1]


def hashkey(k):
    """Hash a key"""
    sha = SHA256.new(k)
    return sha.digest()


def encryptsign_file(key, fl):
    """Encrypt and sign a file"""
    key = hashkey(key)
    iv = urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pad = BLOCK_SIZE - len(fl) % BLOCK_SIZE
    data = fl + pad * chr(pad)
    data = iv + cipher.encrypt(data)
    sig = HMAC.new(key, data, SHA256).digest()

    return data + sig


def decryptsign_file(key, fl):
    """Check signature and decrypt a file"""
    key = hashkey(key)
    sig = fl[-SIG_SIZE:]
    data = fl[:-SIG_SIZE]
    if HMAC.new(key, data, SHA256).digest() != sig:
        raise AuthenticationError
    iv = data[:16]
    data = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = cipher.decrypt(data)

    return data[:-ord(data[-1])]


def return_paths(jso):
    """Return path list of files in a json object response from Drobpox"""
    decodedjson = json.loads(jso)
    paths = [item['path'] for item in decodedjson]

    return paths


def search_file(path, flname, cl):
    """Search for a matching filename in a Dropbox path"""
    try:
        response = cl.search(path, flname)
    except rest.ErrorResponse as e:
        print(e)
        return

    return response


def upload_file(fl, flname, cl):
    """Upload a file to Dropbox"""
    try:
        response = cl.put_file('/' + flname, fl)
    except rest.ErrorResponse as e:
        print(e)
        sys.exit(1)

    print(response)


def download_file(path, fl, cl):
    """Download a file from Dropbox"""
    try:
        response = cl.get_file(path + fl)
    except rest.ErrorResponse as e:
        print(e)
        return e

    return response.read()


def delete_file(fl, cl):
    """Delete a file from the Dropbox folder"""
    try:
        response = cl.file_delete(fl)
    except rest.ErrorResponse as e:
        print(e)
        return e

    return response


def account_info(session):
    """Return a dictionary containing Dropbox account infos"""
    cl = client.DropboxClient(session)
    print((cl.account_info()))

    return cl.account_info()


def connect_app_to_account(key, secret, accesstype):
    """Connect the app to the user's account to obtain an access token"""
    # start Dropbox session
    sess = session.DropboxSession(key, secret, accesstype)
    # obtain a request token
    request_token = sess.obtain_request_token()
    # send the user to the authorize url to allow the app to access his Dropbox account
    url = sess.build_authorize_url(request_token)

    print(url)
    print("Please visit this url, press the 'Allow' button and then hit 'Enter' here")
    input()

    # upgrade the request token to an access one
    access_token = sess.obtain_access_token(request_token)

    return sess, access_token


def handle_encrypt_files(filelist, dbxdir, cl, pwd=False):
    """Encrypt files to the Dropbox folder"""
    for fl in filelist:
        orig_fl = fl
        fl = file_exists(fl, dbxdir)
        if not pwd:
            pwd = ask_password(fl)
        if fl:
            with open(fl, 'rb') as f:
                encrypted_file = encryptsign_file(pwd, f.read())
                output_file = os.path.basename(fl + '.enc')
                with open(output_file, 'wb') as e:
                    e.write(encrypted_file)
                with open(output_file, 'rb') as u:
                    upload_file(u, output_file, cl)
                print(("%s uploaded" % u.name))
                # remove the local file
                os.remove(output_file)
        else:
            print(("%s doesn't exist" % orig_fl))


def handle_decrypt_files(filelist, dbxdir, cl, pwd=False):
    """Decrypt files in the Dropbox directory"""
    for fl in filelist:
        orig_fl = fl
        fl = file_matches(fl, dbxdir)
        if fl:
            dbx_fl = dbxdir + fl
            if not pwd:
                pwd = ask_password(dbx_fl, True)
            with open(dbx_fl, 'rb') as f:
                decrypted_file = decryptsign_file(pwd, f.read())
            with open(os.path.basename(dbx_fl).replace('.enc', ''), 'wb') as o:
                o.write(decrypted_file)
            # then delete the decrypted files from Dropbox
            filef = json.dumps(search_file('/', os.path.basename(dbx_fl), cl))
            paths = return_paths(filef)
            for p in paths:
                del_response = delete_file(p, cl)
            print(("File decrypted to %s" % getcwd()))
        else:
            print(("%s doesn't exist" % orig_fl))

    return


def file_matches(f, dbxdir):
    """Check for a file matching the pattern in the Dropbox directory"""
    names = os.listdir(dbxdir)
    pattern = '*' + f + '*'
    for n in names:
        if n == '.dropbox':
            # do not touch .dropbox file
            pass
        elif fnmatch.fnmatch(n, pattern):
            print(("This file matches: ", n))
            return n
        else:
            pass


def file_exists(f, dbxdir):
    """Check if a file exists in current or Dropbox directory"""
    if not os.path.isfile(f):
        f = os.path.basename(f)
        if not os.path.isfile(dbxdir + f):
            print(("%s doesn't exist" % f))
            sys.exit(1)
        else:
            return dbxdir + f
    else:
        return f


def main():
    # parse cli arguments
    options, cli_parser = argument_parser()

    # import access token and dropbox directory path from the config file
    app_key, app_secret, access_token, dropboxdir = import_config(options.configfile)
    dropboxdir = dropboxdir + '/Apps/' + APP_FOLDER + '/'


    sess = session.DropboxSession(app_key, app_secret, ACCESS_TYPE)
    access_token_secret, access_token = split_token(access_token)

    if not options.filelist:
        raise IOError

    sess.set_token(access_token, access_token_secret)
    
    cl = client.DropboxClient(sess)

    if options.remove:
        # filelist are the pattern to search for removal
        pattern = options.filelist
        for f in pattern:
            # deserialize in a json object and then iterate over the dictionaries
            # in the resulting list to grab the paths of files matching the pattern
            filef = json.dumps(search_file('/', f, cl))
            if len(filef) <= 2:
                # filef contains just the square brackets, therefore it's empty of real data
                print("File not found")
                sys.exit(1)
            paths = return_paths(filef)
            for p in paths:
                del_response = delete_file(p, cl)

        sys.exit(0)

    if options.encrypt:
        if options.singlepass:
            pwd = ask_password(options.filelist, False, True)
            handle_encrypt_files(options.filelist, dropboxdir, cl, pwd)
        else:
            handle_encrypt_files(options.filelist, dropboxdir, cl)
    elif options.decrypt:
        if options.singlepass:
            pwd = ask_password(options.filelist, True, True)
            handle_decrypt_files(options.filelist, dropboxdir, cl, pwd)
        else:
            handle_decrypt_files(options.filelist, dropboxdir, cl)
    else:
        cli_parser.print_help()
        sys.exit(1)
    

if __name__ == '__main__':
    status = main()
    sys.exit(status)
