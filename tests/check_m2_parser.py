#!/usr/bin/env python3
"""Offline checks of p4c's BMv2 parser/deparser JSON with wire-format fixtures.

This small interpreter only supports the JSON operations used by M1/M2 and
fails on unknown operations. It does NOT run BMv2, ingress, egress, checksums
or Mininet, and does not replace the course's runtime regression tests.
Run after make build: python3 tests/check_m2_parser.py
"""

import argparse
import json
import struct
from pathlib import Path


class ParseError(Exception):
    pass


class OfflineParser:
    def __init__(self, program, wire):
        types = {t['name']: t['fields'] for t in program['header_types']}
        self.layouts = {h['name']: types[h['header_type']]
                        for h in program['headers']}
        self.stacks = {s['name']: s['size'] for s in program['header_stacks']}
        self.errors = {code: name for name, code in program['errors']}
        self.program = program
        self.wire = wire
        self.offset = 0
        self.fields = {}
        self.valid = set()
        self.counts = {name: 0 for name in self.stacks}

    def read(self, start, width):
        if start + width > len(self.wire) * 8:
            raise ParseError('PacketTooShort')
        value = int.from_bytes(self.wire, 'big')
        return (value >> (len(self.wire) * 8 - start - width)) & ((1 << width) - 1)

    def field_ref(self, node):
        header, field = node['value']
        if node['type'] == 'stack_field':
            header = f'{header}[{self.counts[header] - 1}]'
        return header, field

    def evaluate(self, node):
        kind, value = node['type'], node['value']
        if kind in ('field', 'stack_field'):
            return self.fields[self.field_ref(node)]
        if kind == 'hexstr':
            return int(value, 16)
        if kind == 'lookahead':
            return self.read(self.offset + value[0], value[1])
        if kind == 'expression':
            if 'op' not in value:
                return self.evaluate(value)
            right = self.evaluate(value['right'])
            op = value['op']
            if op in ('b2d', 'd2b'):
                return int(bool(right))
            left = self.evaluate(value['left'])
            if op == '&':
                return left & right
            if op == '==':
                return int(left == right)
            if op == 'and':
                return int(bool(left) and bool(right))
        raise ValueError(f'Unsupported JSON expression: {node}')

    def extract(self, target):
        name = target['value']
        if target['type'] == 'stack':
            index = self.counts[name]
            if index == self.stacks[name]:
                raise ParseError('StackOutOfBounds')
            self.counts[name] += 1
            name = f'{name}[{index}]'
        else:
            if target['type'] != 'regular':
                raise ValueError(target)
        width = sum(f[1] for f in self.layouts[name])
        self.read(self.offset, width)  # extraction must fit before becoming valid
        for field, bits, *_ in self.layouts[name]:
            self.fields[name, field] = self.read(self.offset, bits)
            self.offset += bits
        self.valid.add(name)

    def run(self):
        parser = self.program['parsers'][0]
        states = {s['name']: s for s in parser['parse_states']}
        name = parser['init_state']
        for _ in range(128):
            if name is None:
                return
            state = states[name]
            for operation in state['parser_ops']:
                op, params = operation['op'], operation['parameters']
                if op == 'extract':
                    self.extract(params[0])
                elif op == 'set':
                    self.fields[self.field_ref(params[0])] = self.evaluate(params[1])
                elif op == 'verify':
                    if not self.evaluate(params[0]):
                        raise ParseError(self.errors[self.evaluate(params[1])])
                else:
                    raise ValueError(f'Unsupported parser operation: {op}')
            # BMv2 pads each select component to a whole number of bytes.
            key = 0
            for component in state['transition_key']:
                header, field = self.field_ref(component)
                bits = next(f[1] for f in self.layouts[header] if f[0] == field)
                key = (key << (((bits + 7) // 8) * 8)) | self.evaluate(component)
            for transition in state['transitions']:
                if transition['type'] == 'default':
                    name = transition['next_state']
                    break
                if transition['type'] != 'hexstr' or transition['mask'] is not None:
                    raise ValueError(f'Unsupported transition: {transition}')
                if key == int(transition['value'], 16):
                    name = transition['next_state']
                    break
            else:
                raise ParseError('NoMatch')
        raise ParseError('ParserTimeout')

    def deparse(self):
        output = bytearray()
        for name in self.program['deparsers'][0]['order']:
            if name not in self.valid:
                continue
            value, width = 0, 0
            for field, bits, *_ in self.layouts[name]:
                value = (value << bits) | self.fields[name, field]
                width += bits
            if width % 8:
                raise ValueError('This check only supports byte-aligned headers')
            output.extend(value.to_bytes(width // 8, 'big'))
        if self.offset % 8:
            raise ValueError('Unaligned payload')
        return bytes(output) + self.wire[self.offset // 8:]


def ethernet(kind, payload):
    return bytes.fromhex('080000000202080000000101') + struct.pack('!H', kind) + payload


def ipv4(protocol, payload, *, ihl=5, fragment=0, source=0x0a000101):
    options = b'\x01' * (4 * (ihl - 5))
    header = struct.pack('!BBHHHBBHII', 0x40 | ihl, 0, 20 + len(options) + len(payload),
                         7, fragment, 64, protocol, 0, source, 0x0a000202)
    # Valid checksum makes the fixture also usable for later real-switch tests.
    words = struct.unpack(f'!{len(header + options) // 2}H', header + options)
    total = sum(words)
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return header[:10] + struct.pack('!H', (~total) & 0xffff) + header[12:] + options + payload


def ipv6(next_header, payload):
    return struct.pack('!IHBB', 0x60000000, len(payload), next_header, 64) + \
        bytes.fromhex('fe800000000000000000000000001234fe800000000000000000000000005678') + payload


def udp(port=5000, data=b'0123456789abcdef'):
    return struct.pack('!HHHH', 49152, port, 8 + len(data), 0) + data


def sr(payload, hops=4):
    return b''.join(struct.pack('!H', (0x8000 if i == hops - 1 else 0) | 2)
                    for i in range(hops)) + payload


def shim(mode, payload, direction=0, magic=0x504f, ether_type=0x0800):
    return struct.pack('!HBIBIH', magic, direction, 0x12345678, mode,
                       0x89abcdef, ether_type) + payload


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('json', nargs='?', type=Path, default=Path('build/polymorphic.json'))
    args = cli.parse_args()
    program = json.loads(args.json.read_text())
    cases = []

    def add(name, kind, payload, valid, error=None, **fields):
        cases.append((name, ethernet(kind, payload), {'ethernet'} | set(valid), error, fields))

    add('IPv4 ICMP remains opaque', 0x0800, ipv4(1, b'\x08\x00' + b'ping' * 4), ['ipv4'])
    add('ordinary UDP non-5000', 0x0800, ipv4(17, udp(4321)), ['ipv4', 'udp'])
    add('UDP non-5000 with shim-like payload', 0x0800,
        ipv4(17, udp(4321, b'PO' + bytes(14))), ['ipv4', 'udp'])
    for size in (0, 4, 15, 17, 32):
        add(f'UDP/5000 payload length {size} remains opaque', 0x0800,
            ipv4(17, udp(data=bytes(size))), ['ipv4', 'udp'])
    add('host UDP/5000 protected data', 0x0800, ipv4(17, udp()),
        ['ipv4', 'udp', 'protected_data'])
    add('IPv4 with options remains opaque', 0x0800, ipv4(17, udp(), ihl=6), ['ipv4'])
    for fragment in (0x2000, 1):
        add(f'IPv4 fragment {fragment} remains opaque', 0x0800,
            ipv4(17, udp(), fragment=fragment), ['ipv4'])
    add('IPv4 DF is allowed', 0x0800, ipv4(17, udp(), fragment=0x4000),
        ['ipv4', 'udp', 'protected_data'])
    tcp = struct.pack('!HHIIBBHHH', 1234, 80, 0, 0, 0x50, 2, 1024, 0, 0)
    add('original IPv4 TCP', 0x0800, ipv4(6, tcp + b'ordinary TCP'), ['ipv4', 'tcp'])
    add('ordinary IPv6 UDP remains opaque', 0x86dd, ipv6(17, udp()), ['ipv6'])
    add('ordinary IPv6 ICMP remains opaque', 0x86dd, ipv6(58, bytes(32)), ['ipv6'])
    arp = struct.pack('!HHBBH6sI6sI', 1, 0x0800, 6, 4, 1,
                      bytes.fromhex('080000000101'), 0x0a000101, bytes(6), 0x0a00010a)
    add('ARP request and destination metadata', 0x0806, arp, ['arp'],
        **{'scalars.metadata.dst_ipv4': 0x0a00010a})
    for hops in (1, 4, 9):
        stack = [f'srcRoutes[{i}]' for i in range(hops)]
        add(f'original SR IPv4 UDP with {hops} hops', 0x1234,
            sr(ipv4(17, udp(4321)), hops), stack + ['ipv4', 'udp'])
    add('original SR IPv4 TCP', 0x1234, sr(ipv4(6, tcp)),
        [f'srcRoutes[{i}]' for i in range(4)] + ['ipv4', 'tcp'])
    add('unknown EtherType remains opaque', 0x88b5, b'opaque bytes', [])
    for mode in (1, 2, 3):
        for direction in (0, 1):
            inner = ipv4(17, udp())
            payload = shim(mode, inner, direction)
            kind = {1: 0x0800, 2: 0x86dd, 3: 0x1234}[mode]
            outer = {1: lambda p: ipv4(253, p, source=0xc0000201),
                     2: lambda p: ipv6(253, p), 3: sr}[mode]
            valid = {1: ['ipv4'], 2: ['ipv6'],
                     3: [f'srcRoutes[{i}]' for i in range(4)]}[mode]
            add(f'mode {mode} direction {direction}', kind, outer(payload),
                valid + ['poly', 'inner_ipv4', 'udp', 'protected_data'],
                **{'poly.direction': direction, 'poly.modality_id': mode,
                   'poly.sequence_number': 0x12345678, 'poly.source_crc32': 0x89abcdef,
                   'inner_ipv4.srcAddr': 0x0a000101,
                   'protected_data.value': int.from_bytes(b'0123456789abcdef', 'big')})
    add('invalid PolyShim magic', 0x0800,
        ipv4(253, shim(1, ipv4(17, udp()), magic=0)), [], 'InvalidPolyShim')
    add('invalid inner EtherType', 0x86dd,
        ipv6(253, shim(2, ipv4(17, udp()), ether_type=0x86dd)), [], 'InvalidPolyShim')
    add('unsupported inner IPv4 options', 0x0800,
        ipv4(253, shim(1, ipv4(17, udp(), ihl=6))), [], 'UnsupportedInnerIPv4')
    add('truncated protected data', 0x0800, ipv4(17, udp()[:-1]), [], 'PacketTooShort')
    add('SR stack overflow', 0x1234, sr(ipv4(17, udp()), 10), [], 'StackOutOfBounds')
    add('truncated PolyShim', 0x86dd, ipv6(253, b'PO'), [], 'PacketTooShort')

    for name, wire, valid, expected_error, fields in cases:
        parser = OfflineParser(program, wire)
        actual_error = None
        try:
            parser.run()
        except ParseError as exc:
            actual_error = str(exc)
        if actual_error != expected_error:
            raise AssertionError((name, actual_error, expected_error))
        if expected_error is None:
            if parser.valid != valid:
                raise AssertionError((name, parser.valid, valid))
            if parser.deparse() != wire:
                raise AssertionError(f'{name}: parser/deparser changed the bytes')
            for field, expected in fields.items():
                if parser.fields[tuple(field.split('.', 1))] != expected:
                    raise AssertionError((name, field))
            if 'poly' in valid and 'ipv4' in valid:
                if parser.fields['ipv4', 'srcAddr'] != 0xc0000201:
                    raise AssertionError('Outer IPv4 was overwritten by inner IPv4')
        print(f'OFFLINE_PASS {name}')
    print(f'OFFLINE_SUMMARY passed={len(cases)}; BMv2/Mininet runtime NOT tested')


if __name__ == '__main__':
    main()
