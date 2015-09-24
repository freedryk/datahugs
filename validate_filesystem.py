#!/usr/bin/env python

from __future__ import print_function, unicode_literals

import argparse
import datetime
from email.mime.text import MIMEText
import hashlib
import getpass
import json
import mmap
from collections import namedtuple
import os
import smtplib
import subprocess as sp
import sys

import memcrc

CHECKSUM_FILENAME = 'CHECKSUM'

def parse_args():
    parser = argparse.ArgumentParser(description='Validate your filesystem')
    parser.add_argument('dirs', metavar="DIRNAME", nargs='+') 
    parser.add_argument('--verbose', action='store_true', default=False)
    parser.add_argument('--clean', action='store_true', default=False) 
    parser.add_argument('--noemail', action='store_true', default=False) 
    parser.add_argument('--method', choices=('shell','python'), default='shell') 

    return parser.parse_args()


def request_email_credentials():
    config = {}

    server = raw_input('Input email server address: ')
    conn = smtplib.SMTP_SSL(server)
    config['server'] = server
    
    username = raw_input('Username: ')
    password = getpass.getpass()
    conn.login(username, password)
    conn.quit()
    config['username'] = username
    config['password'] = password

    config_dir = os.path.expanduser('~/.config/datahugs')
    if not os.path.exists(config_dir):
        os.makedirs(config_dir, 0700)

    config_path = os.path.expanduser('~/.config/datahugs/email.json')
    json.dump(config, open(config_path, 'w'))


def load_email_credentials():
    config_path = os.path.expanduser('~/.config/datahugs/email.json')

    if not os.path.exists(config_path):
        request_email_credentials()
    
    return json.load(open(config_path))


def send_email(config, subject, message):
    msg = MIMEText(message)
    msg['Subject'] = subject
    msg['From'] = 'noreply@datahugs.org'
    msg['To'] = config['username']

    conn = smtplib.SMTP_SSL(config['server'])
    conn.login(config['username'], config['password'])
    conn.sendmail(config['username'], [config['username']], msg.as_string())
    conn.quit()


class Directory(object):
    def __init__(self, path, filenames=None, method='shell',
                 checksum_filename=CHECKSUM_FILENAME):
        self.path = path
        self.checksum_filename = checksum_filename
        if filenames is None:
            self.filenames = [name for name in os.listdir(path) 
                              if not os.path.isdir(os.path.join(path, name))]
        else:
            self.filenames = filenames

        try:
            self.filenames.remove(checksum_filename)
        except ValueError:
            pass

        self.clear()

    def _python_checksum(self):
        self.checksums = {}
        for filename in self.filenames:
            result = {}
            filesize = os.path.getsize(filename)
            result['size'] = str(filesize)
            
            with open(filename, 'rb') as f:
                data = mmap.mmap(f.fileno(), filesize, prot=mmap.PROT_READ)
                file_crc32 = memcrc.memcrc(data)
                result['crc32'] = file_crc32

            self.checksums[filename] = result

    def _shell_checksum(self):
        self.checksums = {}
        if not self.filenames:
            return

        command = ['cksum'] + self.filenames
        shell_output = sp.check_output(command)

        for line in shell_output.splitlines():
            crc32, filesize, filename = line.split(None, 2)
            self.checksums[filename] = {'crc32': crc32, 'size': filesize}

    def calculate_checksums(self, method='shell'):
        self.clear()
        if method == 'python':
            self._python_checksum()
        elif method == 'shell':
            self._shell_checksum()

    def clear(self):
        self.checksums = {}
        self.valid = []
        self.invalid = []
        self.new = []
        self.missing = []

    def read_checksum_file(self):
        self.clear()
        if os.path.exists(self.checksum_filename):
            with open(self.checksum_filename) as f:
                for line in f:
                    crc32, size, filename = line.split()
                    self.checksums[filename] = {'crc32': crc32, 'size': size}

    def write_checksum_file(self):
        with open(self.checksum_filename, 'w') as cf:
            for filename, values in self.checksums.iteritems():
                 cf.write('{crc32} {size} {filename}\n'.format(filename=filename, **values))

    def process(self):
        self.read_checksum_file()
        old_checksums = self.checksums
        
        self.calculate_checksums()
        for filename in old_checksums:
            if filename not in self.checksums:
                self.missing.append(filename)
        
        for filename, checksums in self.checksums.iteritems():
            if filename in old_checksums:
                if checksums == old_checksums[filename]:
                    self.valid.append(filename)
                else:
                    self.invalid.append(filename)
            else:
                self.new.append(filename)


class Checker(object):
    def __init__(self, method='shell'):
        self.cwd = os.getcwd()
        self.method = method
        self.directories = {}

    def process_directory(self, directory, verbose=False):
        for dirpath, _, filenames in os.walk(directory):
            if verbose:
                print(dirpath, filenames)
            if not filenames:
                continue

            os.chdir(dirpath)

            d = Directory(dirpath, filenames=filenames, method=self.method)
            d.process()

            if verbose:
                print(dirpath)
                print('valid: {}'.format(d.valid))
                print('invalid: {}'.format(d.invalid))
                print('new: {}'.format(d.new))
                print('missing: {}'.format(d.missing))

            if d.new and not (d.invalid or d.missing):
                d.write_checksum_file()

            self.directories[dirpath] = d

            os.chdir(self.cwd)

    @property
    def valid(self):
        for dirpath, d in self.directories.iteritems():
            for filename in d.valid:
                yield os.path.join(dirpath, filename)

    @property
    def invalid(self):
        for dirpath, d in self.directories.iteritems():
            for filename in d.invalid:
                yield os.path.join(dirpath, filename)

    @property
    def new(self):
        for dirpath, d in self.directories.iteritems():
            for filename in d.new:
                yield os.path.join(dirpath, filename)

    @property
    def missing(self):
        for dirpath, d in self.directories.iteritems():
            for filename in d.missing:
                yield os.path.join(dirpath, filename)


def clean_directory(directory):
    for dirpath, _, filenames in os.walk(directory):
        if CHECKSUM_FILENAME in filenames:
            os.remove(os.path.join(dirpath, CHECKSUM_FILENAME))


def report_results(checker):

    new = list(checker.new)
    missing = list(checker.missing)
    invalid = list(checker.invalid)

    email_config = load_email_credentials()
    date = str(datetime.date.today())
    if new:
        subject = 'Datahugs report: {} new files {} '.format(len(new), date)
        send_email(email_config, subject, '\n'.join(new))
    if missing:
        subject = 'Datahugs report: {} missing files {} '.format(len(missing), date)
        send_email(email_config, subject, '\n'.join(missing))
    if invalid:
        subject = 'Datahugs report: {} invalid file checksums {} '.format(len(invalid), date)
        send_email(email_config, subject, '\n'.join(invalid))

def main():
    args = parse_args()

    # Check for email credentials
    if not args.noemail:
       load_email_credentials()

    if args.clean:
        # delete all checksum files
        for directory in args.dirs:
            clean_directory(directory)
    else:
        # Calculate checksums and check against previous checksum files
        checker = Checker(args.method)
        for directory in args.dirs:
            checker.process_directory(directory, verbose=args.verbose)

        # Email Result
        if not args.noemail:
            report_results(checker)

        if args.verbose or args.noemail:
            for item in checker.valid:
                print('Valid: {}'.format(item))
            for item in checker.invalid:
                print('Invalid: {}'.format(item))
            for item in checker.new:
                print('New: {}'.format(item))
            for item in checker.missing:
                print('Missing: {}'.format(item))

    sys.exit(0)


if __name__ == "__main__":
    main()
