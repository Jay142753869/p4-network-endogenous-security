#!/usr/bin/env python3
"""Read actual supplied M4 pcaps; never generate captures or launch a network.

Check host input, three source outputs, every intermediate ingress/egress,
destination ingress, and absence of undecided copies at the host output.
File provenance must be recorded separately; a pcap alone cannot prove it.
"""
import argparse
from collections import Counter
from dataclasses import dataclass
import ipaddress
from pathlib import Path
import struct
import zlib

from check_m3_pcaps import read_pcap

IP4 = (ipaddress.ip_address('10.0.1.1').packed, ipaddress.ip_address('10.0.2.2').packed)
IP6 = (ipaddress.ip_address('fe80::1234').packed, ipaddress.ip_address('fe80::5678').packed)


def checksum(raw):
    raw += bytes(len(raw) % 2)
    value = sum(struct.unpack(f'!{len(raw) // 2}H', raw))
    while value >> 16:
        value = (value & 0xffff) + (value >> 16)
    return (~value) & 0xffff


def validate_inner(raw):
    if len(raw) != 44 or raw[0] != 0x45 or raw[9] != 17:
        raise ValueError('expected fixed inner IPv4/UDP/data')
    if struct.unpack('!H', raw[2:4])[0] != 44 or struct.unpack('!H', raw[6:8])[0] & 0xbfff:
        raise ValueError('invalid inner length or fragmentation')
    if struct.unpack('!HH', raw[22:26]) != (5000, 24):
        raise ValueError('expected UDP/5000 length 24')
    return zlib.crc32(raw[12:20] + raw[9:10] + raw[20:24] + raw[28:44])


@dataclass(frozen=True)
class Copy:
    direction: int
    sequence: int
    mode: int
    crc: int
    inner: bytes
    lifetime: int | None
    stack: tuple


def decode(wire):
    if len(wire) < 14:
        raise ValueError('truncated Ethernet')
    if wire[14:16] == b'PO':
        raise ValueError('pending M3 format found; M4 outer header missing')
    kind = struct.unpack('!H', wire[12:14])[0]
    lifetime, stack = None, ()
    if kind == 0x0800:
        if len(wire) < 34 or wire[23] != 253:
            return None
        outer = wire[14:34]
        if outer[0] != 0x45 or struct.unpack('!H', outer[2:4])[0] != 78:
            raise ValueError('invalid outer IPv4 version/IHL/totalLen')
        if checksum(outer) != 0 or struct.unpack('!H', outer[6:8])[0] != 0:
            raise ValueError('invalid outer IPv4 checksum/fragmentation')
        mode, offset, lifetime = 1, 34, outer[8]
        addresses = outer[12:20]
    elif kind == 0x86dd:
        if len(wire) < 54 or wire[20] != 253:
            return None
        outer = wire[14:54]
        if outer[0] >> 4 != 6 or struct.unpack('!H', outer[4:6])[0] != 58:
            raise ValueError('invalid outer IPv6 version/payLoadLen')
        mode, offset, lifetime = 2, 54, outer[7]
        addresses = outer[8:40]
    elif kind == 0x1234:
        ports, offset = [], 14
        for _ in range(9):
            if len(wire) < offset + 2:
                raise ValueError('truncated SR stack')
            entry = struct.unpack('!H', wire[offset:offset + 2])[0]
            ports.append(entry & 0x7fff)
            offset += 2
            if entry & 0x8000:
                break
        else:
            raise ValueError('SR stack missing BOS')
        if wire[offset:offset + 2] != b'PO':
            return None  # ordinary SR/IPv4 is not a polymorphic copy
        mode, stack = 3, tuple(ports)
    else:
        return None
    if len(wire) < offset + 58:
        raise ValueError('truncated PolyShim/inner packet')
    magic, direction, sequence, actual_mode, crc, inner_type = struct.unpack(
        '!HBIBIH', wire[offset:offset + 14])
    if (magic, actual_mode, inner_type) != (0x504f, mode, 0x0800) or direction not in (0, 1):
        raise ValueError('invalid PolyShim or modality mismatch')
    inner = wire[offset + 14:offset + 58]
    if validate_inner(inner) != crc:
        raise ValueError('source_crc32 differs from actual inner fields')
    if inner[12:20] != IP4[direction] + IP4[1 - direction]:
        raise ValueError('unexpected inner address pair')
    if mode in (1, 2):
        pair = IP4 if mode == 1 else IP6
        if addresses != pair[direction] + pair[1 - direction] or lifetime == 0:
            raise ValueError('invalid outer addresses or TTL/hopLimit')
    return Copy(direction, sequence, mode, crc, inner, lifetime, stack)


def host_inputs(path, direction):
    result = []
    for wire in read_pcap(path):
        if len(wire) >= 58 and wire[12:14] == b'\x08\x00' and wire[14] == 0x45 \
                and wire[23] == 17 and wire[36:38] == b'\x13\x88' \
                and wire[26:34] == IP4[direction] + IP4[1 - direction]:
            inner = wire[14:58]
            validate_inner(inner)
            result.append(inner)
    return result


def path_points(direction, mode):
    source, destination = ('s1', 's2') if direction == 0 else ('s2', 's1')
    first, second = {1: ('s11', 's12'), 2: ('s21', 's22'), 3: ('s31', 's32')}[mode]
    if direction:
        first, second = second, first
    in_port, out_port = (1, 2) if direction == 0 else (2, 1)
    port = mode + 1
    return [f'{source}-eth{port}_out.pcap', f'{first}-eth{in_port}_in.pcap',
            f'{first}-eth{out_port}_out.pcap', f'{second}-eth{in_port}_in.pcap',
            f'{second}-eth{out_port}_out.pcap', f'{destination}-eth{port}_in.pcap']


def check(folder, direction, expected=1, scope='full'):
    folder = Path(folder)
    source, destination = ('s1', 's2') if direction == 0 else ('s2', 's1')
    originals = host_inputs(folder / f'{source}-eth1_in.pcap', direction)
    if len(originals) != expected:
        raise ValueError(f'host input: expected {expected}, got {len(originals)}')
    reference = None
    for mode in (1, 2, 3):
        points = path_points(direction, mode)
        if scope == 'source':
            points = points[:1]
        for stage, filename in enumerate(points):
            packets = []
            for wire in read_pcap(folder / filename):
                packet = decode(wire)
                if packet is not None and packet.direction == direction:
                    if packet.mode != mode:
                        raise ValueError(f'{filename}: wrong modality on physical path')
                    if packet.lifetime is not None and packet.lifetime != 64 - stage // 2:
                        raise ValueError(f'{filename}: unexpected TTL/hopLimit')
                    if mode == 3:
                        initial = (2, 2, 1) if direction == 0 else (1, 1, 1)
                        if packet.stack != initial[stage // 2:]:
                            raise ValueError(f'{filename}: wrong SR stack/order/BOS')
                    if stage == 0:
                        expected_dst = bytes.fromhex('080000001100' if direction == 0 else '080000001200')
                        if mode == 3:
                            expected_dst = bytes.fromhex('ffffffffffff')
                        expected_src = bytes.fromhex('080000000100' if direction == 0 else '080000000200')
                        if wire[:12] != expected_dst + expected_src:
                            raise ValueError(f'{filename}: unexpected source-gateway MACs')
                    packets.append(packet)
            if len(packets) != expected or len({p.sequence for p in packets}) != expected:
                raise ValueError(f'{filename}: expected {expected} distinct copies, got {len(packets)}')
            if Counter(p.inner for p in packets) != Counter(originals):
                raise ValueError(f'{filename}: inner packet differs from source host input')
            identity = sorted((p.sequence, p.crc, p.inner) for p in packets)
            if reference is None:
                reference = identity
            if identity != reference:
                raise ValueError(f'{filename}: sequence/CRC/content differs between paths or hops')
    if scope == 'full':
        host_output = folder / f'{destination}-eth1_out.pcap'
        for wire in read_pcap(host_output):
            if decode(wire) is not None:
                raise ValueError(f'{host_output}: undecided outer copy leaked to host')
        if host_inputs(host_output, direction):
            raise ValueError(f'{host_output}: unexpected restored UDP/5000 output before M5/M6')
    return [(seq, crc) for seq, crc, _ in reference]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pcap-dir', type=Path, default=Path('pcaps'))
    parser.add_argument('--direction', type=int, choices=(0, 1), required=True)
    parser.add_argument('--expect', type=int, default=1)
    parser.add_argument('--scope', choices=('source', 'full'), default='full')
    args = parser.parse_args()
    if args.expect < 1:
        parser.error('--expect must be positive')
    try:
        result = check(args.pcap_dir, args.direction, args.expect, args.scope)
    except (OSError, ValueError) as exc:
        parser.exit(1, f'M4_PCAP_FAIL: {exc}\n')
    print(f'M4_PCAP_OK scope={args.scope} direction={args.direction} inputs={len(result)} modalities=3')
    for seq, crc in result:
        print(f'sequence={seq} source_crc32=0x{crc:08x}')
    print('Verified supplied capture contents; capture provenance must be recorded separately.')


if __name__ == '__main__':
    main()
