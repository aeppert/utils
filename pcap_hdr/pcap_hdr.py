#!/usr/bin/python

import os
import sys
import struct
from optparse import OptionParser, OptionGroup

class pcap_header:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.endian = '<'
        self.global_header = None

        self.header_endian = { 0xd4c3b2a1: '<',
                               0xa1b23c4d: '>'  }

        # We use the first 4 bytes, magic_number, to determine the endianness
        # of the remaining bytes in the header
        #
        # typedef struct pcap_hdr_s {
        #     guint32 magic_number;   /* magic number */
        #     guint16 version_major;  /* major version number */
        #     guint16 version_minor;  /* minor version number */
        #     gint32  thiszone;       /* GMT to local correction */
        #     guint32 sigfigs;        /* accuracy of timestamps */
        #     guint32 snaplen;        /* max length of captured packets, in octets */
        #     guint32 network;        /* data link type */
        # } pcap_hdr_t;
        #
        self.header_fmt = '2H4I'
        self.header = 	{ 	'magic_number':  0,
                            'version_major': 0,
                            'version_minor': 0,
                            'thiszone':      0,
                            'sigflags':      0,
                            'snaplen':       0,
                            'network':       0 }
    def __getitem__(self, key):
        ret = None
        try:
            ret = self.header[key]
        except KeyError:
            ret = None
        return ret
    def __get_global_header(self):
        self.global_header = open(self.pcap_file, 'rb').read(struct.calcsize(self.header_fmt) + 4)
    def __get_magic(self):
        if self.global_header:
            (self.header['magic_number'],) = struct.unpack('>I', self.global_header[:4])
            self.endian = self.header_endian[self.header['magic_number']]
    def __get_header_values(self):
        if self.global_header:
            (self.header['version_major'],
             self.header['version_minor'],
             self.header['thiszone'],
             self.header['sigflags'],
             self.header['snaplen'],
             self.header['network']) = struct.unpack(self.endian + self.header_fmt, self.global_header[4:24])
    def process(self):
        self.__get_global_header()
        self.__get_magic()
        self.__get_header_values()
    def dump(self):
        print 'Magic: 0x%x' % (self.header['magic_number'])
        print 'Version: %d.%d' (self.header['version_major'], self.header['version_minor'])
        print 'GMT to Local Correction: %d' % (self.header['thiszone'])
        print 'Accuracy of Timestamps: %d' % (self.header['sigflags'])
        print 'Max Length of Captured Packet (Snaplen): %d' % (self.header['snaplen'])
        print 'Data Link Type: %d' % (self.header['network'])

def main():
    parser = OptionParser()
    parser.add_option('--file', dest='pcap_file', help='PCAP File')
    parser.add_option('--snaplen', action="store_true", dest='snaplen', help='Dump Snaplen', default=False)

    (options, args) = parser.parse_args()

    ph = pcap_header(options.pcap_file)
    ph.process()

    if options.snaplen:
        print ph['snaplen']
    else:
        ph.dump()

if __name__ == '__main__':
    main()

