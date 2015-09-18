#!/usr/bin/env python

from __future__ import print_function, unicode_literals

import argparse
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

checksum_filename = 'CHECKSUM'

def parse_args():
    parser = argparse.ArgumentParser(description='Validate your filesystem')
    parser.add_argument('dirs', metavar="DIRNAME", nargs='+') 
    parser.add_argument('--clean', action='store_true', default=False) 
    parser.add_argument('--noemail', action='store_true', default=False) 
    parser.add_argument('--method', choices=('shell','python'), default='shell') 

    return parser.parse_args()


def request_email_credentials():
    config = {}

    server = raw_input('Input email server address: ')
    conn = smtplib.SMTP_SSL(address)
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
    msg['From'] = config['username']
    msg['To'] = config['username']

    conn = smtplib.SMTP_SSL(config['server'])
    conn.login(config['username'], config['password'])
    conn.sendmail(config['username'], [config['username']], msg.as_string())
    conn.quit()


class CRCchecker(object):
    def __init__(self, method='shell'):
        self.cwd = os.getcwd()
        self.method = method
        self.files = {}

    @staticmethod
    def _python_checksum(filenames):
        results = {}
        for filename in filenames:
            checksums = {}
            filesize = os.path.getsize(filename)
            checksums['size'] = str(filesize)
            
            with open(filename, 'rb') as f:
                data = mmap.mmap(f.fileno(), filesize, prot=mmap.PROT_READ)
                file_crc32 = memcrc.memcrc(data)
                checksums['crc32'] = file_crc32

            results[filename] = checksums

        return results

    @staticmethod
    def _shell_checksum(filenames):
        command = ['cksum'] + filenames
        shell_output = sp.check_output(command)

        results = {}
        for line in shell_output.splitlines():
            crc32, filesize, filename = line.split()
            results[filename] = {'crc32': crc32, 'size': filesize}

        return results

    @staticmethod
    def write_checksum_file(file_checksums):
        with open(checksum_filename, 'w') as cf:
            for filename, values in file_checksums.iteritems():
                 cf.write('{crc32} {size} {filename}\n'.format(filename=filename, **values))

    @staticmethod
    def read_checksums():
        checksums = {}
        with open(checksum_filename) as f:
            for line in f:
                crc32, size, filename = line.split()
                checksums[filename] = {'crc32': crc32, 'size': size}
        return checksums

    def calculate_checksums(self, filenames):
        if self.method == 'python':
            result = self._python_checksum(filenames)
        elif self.method == 'shell':
            result = self._shell_checksum(filenames)
        return result

    def validate_directory(self, checksums):
        valid = []
        invalid = []
        filenames = checksums.keys()
        validation_checksums = self.calculate_checksums(filenames)

        for filename, chksums in checksums.iteritems():
            ok = True
            test_chksums = validation_checksums[filename]
            for name, cksum in chksums.iteritems():
                if test_chksums[name] != cksum:
                    ok = False
                    break
            if ok:
                valid.append(filename)
            else:
                invalid.append((filename, chksums, test_chksums))

        return valid, invalid

    def process_directory(self, directory):
        results = {}
        for dirpath, _, filenames in os.walk(directory):
            print(dirpath, filenames)
            if not filenames:
                continue

            os.chdir(dirpath)

            checksums = {}
            valid_files, invalid_files, missing_files = [], [], []
            if checksum_filename in filenames:
                checksums = self.read_checksums()
                filenames.remove(checksum_filename)
                missing_files = [name for name in filenames if not os.path.exists(name)]
                for filename in missing_files:
                    del checksums[filename]
                valid_files, invalid_files = self.validate_directory(checksums)

            new_files = [name for name in filenames if name not in checksums]

            results[dirpath] = (len(new_files), len(valid_files), missing_files, invalid_files)

            if not invalid_files and new_files:
                new_checksums = self.calculate_checksums(dirpath, new_files)
                checksums.update(new_checksums)
                write_checksum_file(checksums)

            os.chdir(self.cwd)

        return results


def clean_directory(directory):
    for dirpath, _, filenames in os.walk(directory):
        if checksum_filename in filenames:
            os.remove(os.path.join(dirpath, checksum_filename))


def report_results(checker):
    valid, new = 0, 0
    missing = []
    invalid = []
    for dirpath, filestatuses in results.iteritems():
        new += filestatuses[0]
        valid += filestatuses[1]
# TODO concat dirpath & filenames
        missing.extend(filestatuses[2])
        invalid.extend(filestatuses[3])
    
    email_config = load_email_credentials()

    result = [
        "valid: {}".format(valid),
        "new: {}".format(new),
        "missing: {}".format(missing),
        "invalid: {}".format(invalid),
    ]

    if any([new, missing, invalid]):
        subject = 'Datahugs report: {date} {problem}'.format(date=date, problem=problem)
        send_email(email_config, subject, '\n'.join(result))


def main():
    args = parse_args()

    if args.clean:
        for directory in args.dirs:
            clean_directory(directory)
    else:
        checker = CRCchecker(args.method)
        for directory in args.dirs:
            checker.process_directory(directory)
        if not args.noemail:
            report_results(checker)

    sys.exit(0)


if __name__ == "__main__":
    main()
