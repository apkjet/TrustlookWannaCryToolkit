#!/usr/bin/env python
#
# Copyright 2017 Trustlook Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

"""
This is the Trustlook WannaCry Ransomware Scanner, 
please check out the update on our blog:
https://blog.trustlook.com/
"""
import multiprocessing
import socket
import struct
import sys
from impacket import smb
from ipaddr import IPv4Network

def xor_key(s):
    """xor the key"""
    ret = (2 * s ^ (((s & 0xff00 | (s << 16)) << 8) | (((s >> 16) | s & 0xff0000) >> 8)))
    return ret & 0xffffffff

def get_arch(s):
    """the platform arch"""
    return 'x86 (32-bit)' if s == 0 else 'x64 (64-bit)'

def scan(host):
    """scan the host"""
    try:
        s = socket.create_connection((host, 445), timeout=0.5)
        if s is None:
            # port is not open, ignore
            return

        cs = smb.SMB('*SMBSERVER', host, sess_port=445, timeout=0.1)

        uid = cs.login_standard('', '')
        tid = cs.tree_connect_andx('\\\\IPC$', '')
        base_probe = (
            '\x00\x00\x00\x4a\xff\x53\x4d\x42\x25\x00\x00\x00\x00\x18\x01\x28'
            '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + struct.pack('<H', tid) + '\xb9\x1b' +
            struct.pack('<H', cs._uid) + '\xb1\xb6\x10\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00'
            '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4a\x00\x00\x00\x4a\x00\x02'
            '\x00\x23\x00\x00\x00\x07\x00\x5c\x50\x49\x50\x45\x5c\x00'
        )

        doublepulsar_probe = (
            '\x00\x00\x00\x4f\xff\x53\x4d\x42\x32\x00\x00\x00\x00\x18\x07\xc0'
            '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + struct.pack('<H', tid) + '\x4a\x3d' +
            struct.pack('<H', cs._uid) + '\x41\x00\x0f\x0c\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            '\x00\xa6\xd9\xa4\x00\x00\x00\x0c\x00\x42\x00\x00\x00\x4e\x00\x01'
            '\x00\x0e\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            '\x00\x00\x00'
        )
        cs._sess._sock.send(base_probe)
        res = cs._sess._sock.recv(1024)
        status = struct.unpack('<L', res[9:13])[0]

        if status == 0xc0000205:
            # STATUS_INSUFF_SERVER_RESOURCES

            double_infection = False
            try:
                cs._sess._sock.send(doublepulsar_probe)
                res = cs._sess._sock.recv(1024)
                code = struct.unpack('<L', res[34:38])[0]
                sig1 = struct.unpack('<L', res[18:22])[0]
                sig2 = struct.unpack('<L', res[22:26])[0]
                if code == 0x51:
                    double_infection = True
            except:
                pass
            if double_infection:
                print '%s - system is vulnerable, DoublePulsa infection - Arch: %s Key:0x%x ' % \
                      (host, get_arch(sig2),xor_key(sig1))
            else:
                print '%s - system is vulnerable' % host

        elif status == 0xc0000008 or status == 0xc0000022:
            # STATUS_INVALID_HANDLE or STATUS_ACCESS_DENIED
            print '%s - system is not vulnerable' % host
        else:
            print '%s - can not detect vulnerable status' % host
    except:
        pass

def print_usage():
    """print usage"""

    message = """\
Trustlook WannaCry Ransomware Scanner, 
check out our blog https://blog.trustlook.com for udpate

Usage: %s host/network
Example: 
    %s 192.168.0.100 
    %s 192.168.0.0/24""" % (sys.argv[0], sys.argv[0], sys.argv[0])

    print message

def main():
    """main function"""

    if len(sys.argv) != 2:
        print_usage()
        sys.exit(-1)

    print """Trustlook WannaCry Ransomware Scanner
check out our blog https://blog.trustlook.com for udpate
"""
    input_network = sys.argv[1]
    hosts = []

    is_scan_network = '/' in input_network
    if is_scan_network:
        network = IPv4Network(input_network)
        for host in network.iterhosts():
            hosts.append(str(host))
        print 'start to scan network {} for {} hosts...'.format(str(network), len(hosts))
    else:
        print 'start to scan host {}'.format(input_network)
        hosts.append(hosts)

    pool = multiprocessing.Pool(processes=16)
    pool.map(scan, hosts)
    print "done"

if __name__ == '__main__':
    main()
