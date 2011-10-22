#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""A native python implementation of the par2 file format.

This is only intended to be able to read packets in par2, not execute
repair, verify, or create new par2 files."""

import struct

PACKET_HEADER = ("<"
    "8s"  # MAGIC: PAR2\x00PKT
    "Q"   # unsigned 64bit length of entire packet in bytes
    "16s" # md5 of entire packet except first 3 fields
    "16s" # 'setid';  hash of the body of the main packet
    "16s" # packet type
)

FILE_DESCRIPTION_PACKET = ("<64s" # PACKET_HEADER
    "16s" # fileid, hash of [hash16k, length, name]
    "16s" # hashfull;  hash of the whole file (which?)
    "16s" # hash16k;  hash of the first 16k of the file (which?)
    "Q"   # length of the file
)

class Header(object):
    fmt = PACKET_HEADER
    def __init__(self, par2file, offset=0):
        self.raw = par2file[offset:offset+struct.calcsize(self.fmt)]
        parts = struct.unpack(self.fmt, self.raw)
        self.magic = parts[0]
        self.length = parts[1]
        self.hash = parts[2]
        self.setid = parts[3]
        self.type = parts[4]

    def verify(self):
        return self.magic == 'PAR2\x00PKT'

class UnknownPar2Packet(object):
    fmt = PACKET_HEADER
    def __init__(self, par2file, offset=0):
        self.raw = par2file[offset:offset+struct.calcsize(self.fmt)]
        self.header = Header(self.raw)

class FileDescriptionPacket(object):
    header_type = 'PAR 2.0\x00FileDesc'
    fmt = FILE_DESCRIPTION_PACKET

    def __init__(self, par2file, offset=0):
        name_start = offset+struct.calcsize(self.fmt)
        self.raw = par2file[offset:name_start]
        parts = struct.unpack(self.fmt, self.raw)
        self.header = Header(parts[0])
        packet = par2file[offset:offset+self.header.length]
        self.fileid = parts[1]
        self.file_hashfull = parts[2]
        self.file_hash16k = parts[3]
        self.file_length = parts[4]
        self.name = packet[struct.calcsize(self.fmt):].strip('\x00')


class Par2File(object):
    def __init__(self, obj_or_path):
        if isinstance(obj_or_path, basestring):
            self.contents = open(obj_or_path).read()
        else:
            self.contents = obj_or_path.read()
        self.packets = self.read_packets()

    def read_packets(self):
        offset = 0
        filelen = len(self.contents)
        packets = []
        while offset < filelen:
            header = Header(self.contents, offset)
            if header.type == FileDescriptionPacket.header_type:
                packets.append(FileDescriptionPacket(self.contents, offset))
            else:
                packets.append(UnknownPar2Packet(self.contents, offset))
            offset += header.length
        return packets

    def filenames(self):
        return [p.name for p in self.packets if isinstance(p, FileDescriptionPacket)]



