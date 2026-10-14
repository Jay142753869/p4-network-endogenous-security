#!/usr/bin/env python3
"""Read supplied no-fault M6 pcaps; never generate captures or run a network.

Check one input per sequence, three physical paths, destination arrivals and
exactly one restored host output, including all inner bytes and Ethernet MACs.
Capture provenance must be documented separately. This is not a fault checker.
"""
import argparse
from collections import Counter
from pathlib import Path
import re
import struct

from check_m3_pcaps import read_pcap
from check_m4_pcaps import (check as check_source, checksum, decode, host_inputs,
                            path_points, validate_inner, IP4)


def normalized_inner(inner):
    """Only the IPv4 header checksum may be recomputed by restoration."""
    packet = bytearray(inner)
    packet[10:12] = bytes(2)
    packet[10:12] = struct.pack('!H', checksum(bytes(packet[:20])))
    return bytes(packet)


def check_counters(path, gateway, expected):
    lines = [line for line in Path(path).read_text().splitlines()
             if line.startswith(gateway + ' ')]
    if len(lines) != 1:
        raise ValueError(f'{path}: expected exactly one {gateway} counter line')
    values = {key: int(value) for key, value in re.findall(r'(\w+)=([0-9]+)', lines[0])}
    required = {'no_majority': 0}
    for mode in (1, 2, 3):
        required[f'mode{mode}_good'] = expected
        required[f'mode{mode}_bad'] = 0
    if any(values.get(key) != value for key, value in required.items()):
        raise ValueError(f'{path}: unexpected no-fault counters for {gateway}: {values}')


def restored_outputs(path, direction, originals):
    result = []
    sports = {inner[20:22] for inner in originals}
    address_pair = IP4[direction] + IP4[1 - direction]
    host = bytes.fromhex('080000000202' if direction == 0 else '080000000101')
    gateway = bytes.fromhex('080000000200' if direction == 0 else '080000000100')
    for wire in read_pcap(path):
        if decode(wire) is not None:
            raise ValueError(f'{path}: outer PolyShim copy leaked to host')
        if len(wire) < 38 or wire[12:14] != b'\x08\x00' or wire[23] != 17:
            continue
        # Identify the protected flow even if its destination port was changed.
        if wire[36:38] != b'\x13\x88' and not (
                wire[26:34] == address_pair and wire[34:36] in sports):
            continue
        if len(wire) < 58 or len(wire) > 60:
            raise ValueError(f'{path}: invalid restored frame length / leftover headers')
        inner = wire[14:58]
        validate_inner(inner)
        if checksum(inner[:20]) != 0:
            raise ValueError(f'{path}: invalid restored IPv4 checksum')
        if inner[12:20] != address_pair:
            raise ValueError(f'{path}: restored IPv4 addresses changed')
        if wire[:14] != host + gateway + b'\x08\x00':
            raise ValueError(f'{path}: invalid host/gateway Ethernet MACs or EtherType')
        result.append(inner)
    return result


def check(folder, direction, expected=1, counters=None):
    folder = Path(folder)
    source, destination = ('s1', 's2') if direction == 0 else ('s2', 's1')
    # Preserve the M4 checker and its no-output-before-M6 assertions unchanged.
    check_source(folder, direction, expected, scope='source')
    originals = host_inputs(folder / f'{source}-eth1_in.pcap', direction)
    reference = None
    for mode in (1, 2, 3):
        for stage, filename in enumerate(path_points(direction, mode)):
            packets = [packet for wire in read_pcap(folder / filename)
                       if (packet := decode(wire)) is not None and packet.direction == direction]
            if len(packets) != expected or len({p.sequence for p in packets}) != expected:
                raise ValueError(f'{filename}: expected {expected} distinct sequence arrivals')
            for packet in packets:
                if packet.mode != mode:
                    raise ValueError(f'{filename}: modality on wrong physical path')
                if packet.lifetime is not None and packet.lifetime != 64 - stage // 2:
                    raise ValueError(f'{filename}: incorrect TTL/hopLimit')
                if mode == 3:
                    initial = (2, 2, 1) if direction == 0 else (1, 1, 1)
                    if packet.stack != initial[stage // 2:]:
                        raise ValueError(f'{filename}: incorrect SR stack/BOS order')
            identity = sorted((p.sequence, p.crc, p.inner) for p in packets)
            if reference is None:
                reference = identity
            if identity != reference:
                raise ValueError(f'{filename}: sequence/CRC/inner mismatch across paths')

    wanted = [normalized_inner(inner) for _, _, inner in reference]
    # PolyShim is removed on host output, so identical datagrams cannot be
    # unambiguously assigned back to different sequences. Refuse that claim.
    if len(set(wanted)) != len(wanted):
        raise ValueError('ambiguous identical inputs: use distinct payloads/UDP ports per sequence')
    outputs = restored_outputs(folder / f'{destination}-eth1_out.pcap', direction, originals)
    if len(outputs) != expected or Counter(outputs) != Counter(wanted):
        raise ValueError(f'{destination} host output: expected exactly one byte-correct packet per sequence; '
                         f'wanted {expected}, got {len(outputs)}')
    if counters is not None:
        check_counters(counters, destination, expected)
    return [(sequence, crc, inner[28:44].hex()) for sequence, crc, inner in reference]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pcap-dir', type=Path, default=Path('pcaps'))
    parser.add_argument('--direction', type=int, choices=(0, 1), required=True)
    parser.add_argument('--expect', type=int, default=1)
    parser.add_argument('--counters', type=Path, help='fresh-pipeline read-counters.py output')
    args = parser.parse_args()
    if args.expect < 1:
        parser.error('--expect must be positive')
    try:
        result = check(args.pcap_dir, args.direction, args.expect, args.counters)
    except (OSError, ValueError) as exc:
        parser.exit(1, f'M6_PCAP_FAIL: {exc}\n')
    print(f'M6_PCAP_OK direction={args.direction} inputs={len(result)} modalities=3 '
          f'host_outputs={len(result)} per_sequence=1')
    for sequence, crc, protected in result:
        print(f'sequence={sequence} source_crc32=0x{crc:08x} protected_hex={protected} host_outputs=1')
    print('Verified supplied capture contents; capture provenance must be recorded separately.')


if __name__ == '__main__':
    main()
