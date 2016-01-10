#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""A native python implementation of the par2 file format.

This is only intended to be able to read packets in par2, not repair,
verify, or create new par2 files."""

import os
import glob
import struct

from par2ools import fileutil

PACKET_HEADER = ("<"
    "8s"  # MAGIC: PAR2\x00PKT
    "Q"   # unsigned 64bit length of entire packet in bytes
    "16s" # md5 of entire packet except first 3 fields
    "16s" # 'setid';  hash of the body of the main packet
    "16s" # packet type
)

FILE_DESCRIPTION_PACKET = ("<64s" # PACKET_HEADER
    "16s" # fileid; file this packet belongs to
    "16s" # hashfull;  md5 hash of the whole file
    "16s" # hash16k;  md5 hash of the first 16k of the file
    "Q"   # length of the file
)

MAIN_PACKET = ("<64s" # PACKET_HEADER
    "Q" # slice_size; The size of the slices in bytes
    "I" # num_files; Number of files in the recovery set
)

MAIN_PACKET_FILEID = ("<"
    "16s" # fileid;
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

class MainPacket(object):
    fmt = MAIN_PACKET
    fmt_array = MAIN_PACKET_FILEID
    header_type = 'PAR 2.0\x00Main\x00\x00\x00\x00'

    def __init__(self, par2file, offset=0):
        array_start = struct.calcsize(self.fmt)
        parts = struct.unpack(self.fmt, par2file[offset:offset+array_start])
        self.header = Header(parts[0])
        self.slice_size = parts[1]
        self.num_files = parts[2]
        hash_size = struct.calcsize(self.fmt_array)
        num_ids = (self.header.length - array_start) / hash_size
        self.file_ids = []
        for idx in range(num_ids):
            start = offset + array_start + (hash_size * idx)
            parts = struct.unpack(self.fmt_array, par2file[start:start+hash_size])
            self.file_ids.append(parts[0])
        self.num_nonrecovery_files = self.num_files - num_ids

class Par2File(object):
    def __init__(self, obj_or_path):
        """A convenient object that reads and makes sense of Par2 blocks."""
        self.path = None
        if isinstance(obj_or_path, basestring):
            with open(obj_or_path) as f:
                self.contents = f.read()
                self.path = obj_or_path
        else:
            self.contents = obj_or_path.read()
            if getattr(obj_or_path, 'name', None):
                self.path = obj_or_path.name
        self.main_packet = None
        self.packets = self.read_packets()

    def read_packets(self):
        offset = 0
        filelen = len(self.contents)
        packets = []
        while offset < filelen:
            header = Header(self.contents, offset)
            if header.type == MainPacket.header_type:
                self.main_packet = MainPacket(self.contents, offset)
                packets.append(self.main_packet)
            elif header.type == FileDescriptionPacket.header_type:
                packets.append(FileDescriptionPacket(self.contents, offset))
            else:
                packets.append(UnknownPar2Packet(self.contents, offset))
            offset += header.length
        return packets

    def filenames(self):
        """Returns the filenames that this par2 file repairs."""
        return [p.name for p in self.packets if isinstance(p, FileDescriptionPacket)]

    def related_pars(self):
        """Returns a list of related par2 files (ones par2 will try to read
        from to find file recovery blocks).  If this par2 file was a file-like
        object (like a StringIO) without an associated path, return [].
        Otherwise, the name of this file + associated files are returned."""
        if not self.path:
            return []
        names = [self.path]
        basename = self.path.replace('.par2', '').replace('.PAR2', '')
        names += fileutil.cibaseglob('*.vol*.PAR2', basename)
        return names

