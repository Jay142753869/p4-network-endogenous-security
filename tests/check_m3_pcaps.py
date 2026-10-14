#!/usr/bin/env python3
"""Check three source-port captures of M3's pending (unencapsulated) copies.

This reads supplied classic Ethernet pcaps; it never launches a switch or
claims that the captures came from BMv2. It is intentionally specific to M3's
Ethernet / PolyShim(mode=0) / inner IPv4 / UDP / protected_data staging order.
"""
import argparse
import struct
import zlib
from pathlib import Path


def read_pcap(path):
    with Path(path).open('rb') as stream:
        header = stream.read(24)
        orders = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>',
                  b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\x3c\x4d': '>'}
        if len(header) != 24 or header[:4] not in orders:
            raise ValueError(f'{path}: expected classic pcap, not pcapng')
        order = orders[header[:4]]
        if struct.unpack(order + 'I', header[20:24])[0] != 1:
            raise ValueError(f'{path}: expected Ethernet link type')
        while True:
            record = stream.read(16)
            if not record:
                return
            if len(record) != 16:
                raise ValueError(f'{path}: incomplete pcap record')
            _, _, captured, original = struct.unpack(order + 'IIII', record)
            if captured != original:
                raise ValueError(f'{path}: truncated capture')
            wire = stream.read(captured)
            if len(wire) != captured:
                raise ValueError(f'{path}: incomplete packet')
            yield wire


def pending_packets(path, direction):
    packets = []
    for wire in read_pcap(path):
        if wire[14:16] != b'PO':
            continue  # ignore ordinary IPv4/IPv6/ARP/SR frames
        if len(wire) < 72:
            raise ValueError(f'{path}: truncated M3 pending packet')
        magic, actual_direction, sequence, mode, source_crc, inner_type = struct.unpack(
            '!HBIBIH', wire[14:28])
        if (magic, actual_direction, mode, inner_type) != (0x504f, direction, 0, 0x0800):
            raise ValueError(f'{path}: unexpected pending PolyShim')
        ip, udp, data = wire[28:48], wire[48:56], wire[56:72]
        if ip[0] != 0x45 or ip[9] != 17 or struct.unpack('!H', ip[2:4])[0] != 44:
            raise ValueError(f'{path}: unexpected inner IPv4')
        if struct.unpack('!HH', udp[2:6]) != (5000, 24):
            raise ValueError(f'{path}: unexpected UDP')
        raw = ip[12:20] + ip[9:10] + udp[:4] + data
        if zlib.crc32(raw) != source_crc:
            raise ValueError(f'{path}: CRC mismatch for sequence {sequence}')
        packets.append((sequence, source_crc, wire))
    return packets


def check(paths, direction, expected):
    captures = [pending_packets(path, direction) for path in paths]
    for path, packets in zip(paths, captures):
        if len(packets) != expected or len({p[0] for p in packets}) != expected:
            raise ValueError(f'{path}: expected {expected} distinct pending packets, got {len(packets)}')
    # Compare by sequence, permitting different packet order on each output.
    normalized = [sorted(packets) for packets in captures]
    if normalized[0] != normalized[1] or normalized[0] != normalized[2]:
        raise ValueError('The three source outputs differ in sequence, CRC or packet bytes')
    return [(sequence, crc) for sequence, crc, _ in normalized[0]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--direction', type=int, choices=(0, 1), required=True)
    parser.add_argument('--expect', type=int, required=True, help='source inputs per output port')
    parser.add_argument('pcaps', type=Path, nargs=3, help='source ports 2, 3, 4 output pcaps')
    args = parser.parse_args()
    if args.expect < 1:
        parser.error('--expect must be positive')
    try:
        result = check(args.pcaps, args.direction, args.expect)
    except (OSError, ValueError) as exc:
        parser.exit(1, f'PCAP_CHECK_FAIL: {exc}\n')
    print(f'PCAP_CHECK_OK direction={args.direction} per_port={len(result)} copies={len(result) * 3}')
    for sequence, crc in result:
        print(f'sequence={sequence} source_crc32=0x{crc:08x}')
    print('Source captures checked; M4 encapsulation and end-to-end delivery are NOT checked.')


if __name__ == '__main__':
    main()
