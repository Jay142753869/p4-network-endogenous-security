#!/usr/bin/env python3
"""Read supplied final-scenario pcaps, including actual XOR/drop locations.

Never generates captures, installs rules or adjudicates packets. Expected
scenarios are read from the unchanged official runner. Capture provenance
must be recorded separately; this checker cannot prove how a file was made.
"""
import argparse
import ast
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
import re
import struct

from check_m3_pcaps import read_pcap
from check_m4_pcaps import IP4, IP6, checksum, host_inputs, path_points, validate_inner
from check_m6_pcaps import normalized_inner, restored_outputs

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = next(ast.literal_eval(node.value)
                 for node in ast.parse((ROOT / 'run-poly-tests.py').read_text()).body
                 if isinstance(node, ast.Assign) and any(
                     isinstance(target, ast.Name) and target.id == 'SCENARIOS' for target in node.targets))


@dataclass(frozen=True)
class Copy:
    direction: int
    sequence: int
    mode: int
    source_crc: int
    observed_crc: int
    inner: bytes
    lifetime: int | None
    stack: tuple


def decode_copy(wire):
    """Decode received bytes without requiring observed_crc == source_crc."""
    if len(wire) < 14:
        raise ValueError('truncated Ethernet')
    kind = struct.unpack('!H', wire[12:14])[0]
    lifetime, stack, addresses = None, (), None
    if kind == 0x0800:
        if len(wire) < 34:
            raise ValueError('truncated IPv4')
        if wire[23] != 253:
            return None
        outer = wire[14:34]
        if outer[0] != 0x45 or struct.unpack('!H', outer[2:4])[0] != 78 \
                or checksum(outer) != 0 or outer[6:8] != bytes(2):
            raise ValueError('invalid outer IPv4 format/checksum')
        mode, offset, lifetime, addresses = 1, 34, outer[8], outer[12:20]
    elif kind == 0x86dd:
        if len(wire) < 54:
            raise ValueError('truncated IPv6')
        if wire[20] != 253:
            return None
        outer = wire[14:54]
        if outer[0] >> 4 != 6 or struct.unpack('!H', outer[4:6])[0] != 58:
            raise ValueError('invalid outer IPv6 format')
        mode, offset, lifetime, addresses = 2, 54, outer[7], outer[8:40]
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
            return None
        mode, stack = 3, tuple(ports)
    else:
        return None
    if len(wire) < offset + 58:
        raise ValueError('truncated PolyShim/inner')
    magic, direction, sequence, actual_mode, source_crc, inner_type = struct.unpack(
        '!HBIBIH', wire[offset:offset + 14])
    if (magic, actual_mode, inner_type) != (0x504f, mode, 0x0800) or direction not in (0, 1):
        raise ValueError('invalid PolyShim / modality')
    inner = wire[offset + 14:offset + 58]
    observed = validate_inner(inner)  # full 232-bit order used by M3/M5
    if inner[12:20] != IP4[direction] + IP4[1 - direction]:
        raise ValueError('unexpected inner IP addresses')
    if mode in (1, 2):
        pair = IP4 if mode == 1 else IP6
        if addresses != pair[direction] + pair[1 - direction] or lifetime == 0:
            raise ValueError('unexpected outer addresses/lifetime')
    return Copy(direction, sequence, mode, source_crc, observed, inner, lifetime, stack)


def expected_stats(scenario):
    good, bad, no_majority = [1, 1, 1], [0, 0, 0], 0
    if scenario == 'corrupt-mode1':
        good[0], bad[0] = 0, 1
    elif scenario == 'drop-mode2':
        good[1] = 0
    elif scenario == 'no-majority':
        good, no_majority = [0, 0, 0], 1
    return good, bad, no_majority


def check_counters(path, destination, scenario):
    lines = Path(path).read_text().splitlines()
    for gateway in ('s1', 's2'):
        candidates = [line for line in lines if line.startswith(gateway + ' ')]
        if len(candidates) != 1:
            raise ValueError(f'{path}: expected one counter line for {gateway}')
        good, bad, no_majority = expected_stats(scenario) if gateway == destination \
            else ([0, 0, 0], [0, 0, 0], 0)
        values = {key: int(value) for key, value in re.findall(r'(\w+)=([0-9]+)', candidates[0])}
        required = {'no_majority': no_majority}
        for mode in (1, 2, 3):
            required[f'mode{mode}_good'] = good[mode - 1]
            required[f'mode{mode}_bad'] = bad[mode - 1]
        if any(values.get(key) != value for key, value in required.items()):
            raise ValueError(f'{path}: {gateway} counters differ from the clean {scenario} expectation')


def check(folder, scenario, counters=None, direction=None):
    folder = Path(folder)
    config = SCENARIOS[scenario]
    direction = int(config['sender'] == 'h2') if direction is None else direction
    source, destination = ('s1', 's2') if direction == 0 else ('s2', 's1')
    originals = host_inputs(folder / f'{source}-eth1_in.pcap', direction)
    if len(originals) != 1:
        raise ValueError(f'{source}: expected exactly one original host input')
    original = originals[0]
    source_crc = validate_inner(original)
    faults = {}
    for rule in config['faults']:
        parts = rule.split(':')
        faults[int(parts[1])] = (parts[0], int(parts[2]), int(parts[3], 0) if len(parts) == 4 else 0)
    observations = {}
    for mode in (1, 2, 3):
        operation, target_seq, mask = faults.get(mode, ('none', 1, 0))
        # Official scenarios start a fresh source and target sequence 1.
        if target_seq != 1:
            raise ValueError('official scenario expected SEQ=1')
        changed = original[:28] + (int.from_bytes(original[28:44], 'big') ^ mask).to_bytes(16, 'big')
        fault_ingress_stage = 1 if direction == 0 else 3
        points = path_points(direction, mode)
        for stage, filename in enumerate(points):
            packets = [p for wire in read_pcap(folder / filename)
                       if (p := decode_copy(wire)) is not None and p.direction == direction]
            after_fault = stage > fault_ingress_stage
            wanted_count = 0 if operation == 'drop' and after_fault else 1
            if len(packets) != wanted_count:
                raise ValueError(f'{filename}: expected {wanted_count} copy, got {len(packets)}')
            if not packets:
                continue
            packet = packets[0]
            wanted_inner = changed if operation == 'corrupt' and after_fault else original
            if packet.sequence != 1 or packet.mode != mode or packet.inner != wanted_inner:
                raise ValueError(f'{filename}: sequence/modality/actual XOR bytes mismatch')
            if packet.source_crc != source_crc:
                raise ValueError(f'{filename}: source_crc32 was altered')
            if packet.observed_crc != validate_inner(wanted_inner):
                raise ValueError(f'{filename}: observed CRC mismatch')
            if packet.lifetime is not None and packet.lifetime != 64 - stage // 2:
                raise ValueError(f'{filename}: outer lifetime / physical path mismatch')
            if mode == 3:
                initial = (2, 2, 1) if direction == 0 else (1, 1, 1)
                if packet.stack != initial[stage // 2:]:
                    raise ValueError(f'{filename}: SR stack / BOS mismatch')
            if stage == 0:
                source_wire = next(wire for wire in read_pcap(folder / filename)
                                   if (p := decode_copy(wire)) is not None and p.direction == direction)
                src_mac = bytes.fromhex('080000000100' if direction == 0 else '080000000200')
                dst_mac = bytes.fromhex('ffffffffffff' if mode == 3 else
                                       '080000001100' if direction == 0 else '080000001200')
                if source_wire[:12] != dst_mac + src_mac:
                    raise ValueError(f'{filename}: source gateway MAC mismatch')
            if stage == 5:
                observations[mode] = packet.observed_crc
        if operation == 'drop':
            observations[mode] = None
    if scenario == 'no-majority' and len(set(observations.values())) != 3:
        raise ValueError('no-majority requires three distinct actual observed CRCs')
    outputs = restored_outputs(folder / f'{destination}-eth1_out.pcap', direction, originals)
    wanted_outputs = [normalized_inner(original)] * config['expected']
    if Counter(outputs) != Counter(wanted_outputs):
        raise ValueError(f'{destination}: expected {config["expected"]} exact original host output(s), '
                         f'got {len(outputs)}')
    if counters is not None:
        check_counters(counters, destination, scenario)
    return source_crc, observations, len(outputs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pcap-dir', type=Path, required=True)
    parser.add_argument('--scenario', choices=tuple(SCENARIOS), required=True)
    parser.add_argument('--counters', type=Path)
    parser.add_argument('--direction', type=int, choices=(0, 1), help='override for reverse fault probes')
    args = parser.parse_args()
    try:
        source, observed, count = check(args.pcap_dir, args.scenario, args.counters, args.direction)
    except (OSError, ValueError) as exc:
        parser.exit(1, f'FINAL_PCAP_FAIL: {exc}\n')
    print(f'FINAL_PCAP_OK scenario={args.scenario} source_crc32=0x{source:08x} host_outputs={count}')
    for mode, crc in sorted(observed.items()):
        print(f'mode={mode} observed_crc=' + ('MISSING' if crc is None else f'0x{crc:08x}'))
    print('Checked actual injection ingress/egress, downstream paths and host output; '
          'capture provenance must be recorded separately.')


if __name__ == '__main__':
    main()
