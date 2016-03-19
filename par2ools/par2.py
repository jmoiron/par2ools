#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""A native python implementation of the par2 file format.

This is only intended to be able to read packets in par2, not repair,
verify, or create new par2 files."""

import struct
import hashlib

from par2ools import fileutil

PACKET_HEADER = ("<"
    "8s"  # MAGIC: PAR2\x00PKT
    "Q"   # unsigned 64bit length of entire packet in bytes
    "16s" # md5 of entire packet except first 3 fields
    "16s" # 'setid';  hash of the body of the main packet
    "16s" # packet type
)

FILE_DESCRIPTION_PACKET = ("<"
    "16s" # fileid; file this packet belongs to
    "16s" # hashfull;  md5 hash of the whole file
    "16s" # hash16k;  md5 hash of the first 16k of the file
    "Q"   # length of the file
)

MAIN_PACKET = ("<"
    "Q" # slice_size; The size of the slices in bytes
    "I" # num_files; Number of files in the recovery set
)

MAIN_PACKET_FILEID = ("<"
    "16s" # fileid;
)

FILE_CHECKSUM_PACKET = ("<"
    "16s" # fileid; file this packet belongs to
)

FILE_CHECKSUM_PACKET_SLICE = ("<"
    "16s" # hash; MD5 hash of the slice
    "i" # checksum; CRC32 checksum of the slice
)

class Header(object):
    fmt = PACKET_HEADER
    size = struct.calcsize(PACKET_HEADER) # Size of just the header

    def __init__(self, raw):
        parts = struct.unpack(self.fmt, raw)
        self.magic = parts[0]
        self.length = parts[1] # Length of the full packet (including header)
        self.body_length = self.length - self.size
        self.hash = parts[2]
        self.setid = parts[3]
        self.type = parts[4]

    def verify(self):
        return self.magic == 'PAR2\x00PKT'

    def verify_packet(self, raw_packet):
        if len(raw_packet) < self.length:
            return False
        validate_start = 8 + 8 + 16 #  Skip the first 3 fields
        raw = raw_packet[validate_start:]
        return hashlib.md5(raw).digest() == self.hash

class UnknownPar2Packet(object):
    fmt = PACKET_HEADER
    def __init__(self, header, raw):
        self.raw = raw
        self.header = header

class FileDescriptionPacket(object):
    header_type = 'PAR 2.0\x00FileDesc'
    fmt = FILE_DESCRIPTION_PACKET

    def __init__(self, header, raw):
        self.header = header
        name_start = struct.calcsize(self.fmt)
        parts = struct.unpack(self.fmt, raw[:name_start])
        self.fileid = parts[0]
        self.file_hashfull = parts[1]
        self.file_hash16k = parts[2]
        self.file_length = parts[3]
        self.name = raw[name_start:].strip('\x00')

class MainPacket(object):
    fmt = MAIN_PACKET
    fmt_array = MAIN_PACKET_FILEID
    header_type = 'PAR 2.0\x00Main\x00\x00\x00\x00'

    def __init__(self, header, raw):
        self.header = header
        array_start = struct.calcsize(self.fmt)
        parts = struct.unpack(self.fmt, raw[:array_start])
        self.slice_size = parts[0]
        self.num_files = parts[1]
        hash_size = struct.calcsize(self.fmt_array)
        num_ids = (self.header.length - self.header.size - array_start) / hash_size
        self.file_ids = []
        for idx in range(num_ids):
            start = array_start + (hash_size * idx)
            parts = struct.unpack(self.fmt_array, raw[start:start+hash_size])
            self.file_ids.append(parts[0])
        self.num_nonrecovery_files = self.num_files - num_ids

class InputFileSliceChecksumPacket(object):
    fmt = FILE_CHECKSUM_PACKET
    slice_fmt = FILE_CHECKSUM_PACKET_SLICE
    header_type = 'PAR 2.0\x00IFSC\x00\x00\x00\x00'

    def __init__(self, header, raw):
        self.header = header
        body_size = struct.calcsize(self.fmt)
        parts = struct.unpack(self.fmt, raw[:body_size])
        self.fileid = parts[0]
        # Unpack slices
        slice_size = struct.calcsize(self.slice_fmt)
        self.num_slices = (self.header.length - (body_size + header.size)) / slice_size
        self.slice_md5 = []
        self.slice_crc = []
        for idx in range(self.num_slices):
            start = body_size + (slice_size * idx)
            parts = struct.unpack(self.slice_fmt, raw[start:start+slice_size])
            self.slice_md5.append(parts[0])
            self.slice_crc.append(parts[1])

class Par2File(object):
    def __init__(self, obj_or_path):
        """A convenient object that reads and makes sense of Par2 blocks."""
        self.path = None
        self.main_packet = None
        if isinstance(obj_or_path, basestring):
            self.path = obj_or_path
            with open(obj_or_path) as fle:
                self.packets = self.read_packets(fle)
        else:
            if getattr(obj_or_path, 'name', None):
                self.path = obj_or_path.name
            self.packets = self.read_packets(obj_or_path)

    def read_packets(self, fle):
        packets = []
        while True:
            raw_header = fle.read(Header.size)
            if not raw_header:
                break #  catch EOF
            header = Header(raw_header)
            if not header.verify():
                break
            raw_body = fle.read(header.body_length)
            if not header.verify_packet(raw_header + raw_body):
                # If the packet was invalid, we cant trust the length to skip
                # to the next packet, so abort with what we have already.
                break
            if header.type == MainPacket.header_type:
                self.main_packet = MainPacket(header, raw_body)
                packets.append(self.main_packet)
            elif header.type == FileDescriptionPacket.header_type:
                packets.append(FileDescriptionPacket(header, raw_body))
            elif header.type == InputFileSliceChecksumPacket.header_type:
                packets.append(InputFileSliceChecksumPacket(header, raw_body))
            else:
                packets.append(UnknownPar2Packet(header, raw_body))
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

