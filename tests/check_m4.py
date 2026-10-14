#!/usr/bin/env python3
"""OFFLINE ONLY: interpret compiled JSON, controller protobufs and checksum model.

Synthetic multi-hop traces and temporary pcaps are checker fixtures, never
BMv2 runtime evidence. No socket or Mininet process is created.
"""
import ipaddress
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from check_m2_parser import ethernet, ipv4, ipv6, sr, udp
from check_m3 import OfflineIngress, RecordingSwitch, ROOT, controller, P4InfoHelper
from check_m4_pcaps import check as check_pcaps, checksum, decode, path_points


def controller_entries(helper):
    switches = {}
    def connect(**kwargs):
        sw = RecordingSwitch(**kwargs)
        switches[sw.name] = sw
        return sw
    with patch.object(controller.p4runtime_lib.bmv2, 'Bmv2SwitchConnection', side_effect=connect), \
            patch.object(controller, 'ShutdownAllSwitchConnections'):
        controller.main(str(ROOT / 'build/polymorphic.p4.p4info.txtpb'),
                        str(ROOT / 'build/polymorphic.json'))
    return {name: [r.updates[0].entity.table_entry for r in sw.requests
                   if r.updates[0].entity.HasField('table_entry')]
            for name, sw in switches.items()}


class OfflineSwitch(OfflineIngress):
    def __init__(self, program, wire, helper, entries, port=1, registers=None):
        self.helper, self.entries = helper, entries
        super().__init__(program, wire, port=port, registers=registers)

    def configured_action(self, table):
        if not table['key']:
            return None
        candidates = [e for e in self.entries
                      if self.helper.get_tables_name(e.table_id) == table['name']]
        # Explicit entries take precedence over configurable default actions.
        candidates.sort(key=lambda e: e.is_default_action)
        for entry in candidates:
            matches = True
            for key in ([] if entry.is_default_action else table['key']):
                field_id = self.helper.get_match_field_id(table['name'], key['name'])
                field = next(f for f in entry.match if f.field_id == field_id)
                actual = self.fields[tuple(key['target'])]
                if field.HasField('exact'):
                    matches &= actual == int.from_bytes(field.exact.value, 'big')
                elif field.HasField('lpm'):
                    width = self.widths[tuple(key['target'])]
                    shift = width - field.lpm.prefix_len
                    matches &= actual >> shift == int.from_bytes(field.lpm.value, 'big') >> shift
                else:
                    raise ValueError('unsupported configured match')
            if matches:
                name = self.helper.get_actions_name(entry.action.action.action_id)
                action_id = next(i for i in table['action_ids'] if self.actions[i]['name'] == name)
                values = {self.helper.get_action_param_name(name, p.param_id):
                          int.from_bytes(p.value, 'big') for p in entry.action.action.params}
                return action_id, [values[p['name']] for p in self.actions[action_id]['runtime_data']], \
                    not entry.is_default_action
        return None

    def pipeline(self, name):
        pipeline = next(p for p in self.program['pipelines'] if p['name'] == name)
        conditions = {c['name']: c for c in pipeline['conditionals']}
        tables = {t['name']: t for t in pipeline['tables']}
        node = pipeline['init_table']
        for _ in range(128):
            if node is None:
                return self
            self.visited.append(node)
            if node in conditions:
                c = conditions[node]
                node = c['true_next'] if self.evaluate(c['expression']) else c['false_next']
                continue
            table = tables[node]
            configured = self.configured_action(table)
            default = table['default_entry']
            action_id, data, hit = configured if configured is not None else (
                default['action_id'], [int(v, 16) for v in default['action_data']], False)
            if self.execute(action_id, data):
                return self
            successors = table['next_tables']
            node = successors['__HIT__' if hit else '__MISS__'] if '__HIT__' in successors \
                else successors[self.actions[action_id]['name']]
        raise ValueError(f'{name} did not terminate')

    def egress(self, port=None, replication=False):
        self.fields['standard_metadata', 'egress_port'] = port if port is not None \
            else self.fields['standard_metadata', 'egress_spec']
        self.fields['standard_metadata', 'instance_type'] = 5 if replication else 0
        # An unrelated rid must not influence port-based format selection.
        self.fields['standard_metadata', 'egress_rid'] = 99
        self.pipeline('egress')
        for update in self.program['checksums']:
            if not update['update'] or not self.evaluate(update['if_cond']):
                continue
            calc = next(c for c in self.program['calculations'] if c['name'] == update['calculation'])
            if calc['algo'] != 'csum16':
                raise ValueError(calc)
            value, bits = 0, 0
            for field in calc['input']:
                width = self.widths[self.field_ref(field)]
                value = (value << width) | self.evaluate(field)
                bits += width
            if bits % 8:
                raise ValueError('unaligned checksum input')
            self.fields[tuple(update['target'])] = checksum(value.to_bytes(bits // 8, 'big'))
        return self


class M4Checks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.program = json.loads((ROOT / 'build/polymorphic.json').read_text())
        cls.helper = P4InfoHelper(str(ROOT / 'build/polymorphic.p4.p4info.txtpb'))
        cls.entries = controller_entries(cls.helper)

    def node(self, wire, name, port=1, entries=None):
        return OfflineSwitch(self.program, wire, self.helper,
                             self.entries[name] if entries is None else entries, port=port)

    def original(self, direction=0):
        inner = bytearray(ipv4(17, udp()))
        if direction:
            inner[12:20] = inner[16:20] + inner[12:16]
            inner[10:12] = bytes(2)
            inner[10:12] = struct.pack('!H', checksum(bytes(inner[:20])))
        return ethernet(0x0800, bytes(inner))

    def source(self, direction, port):
        p = self.node(self.original(direction), 's1' if direction == 0 else 's2')
        p.pipeline('ingress')
        return p.egress(port, replication=True)

    def test_six_encapsulations_validity_lengths_and_immutable_inner(self):
        for direction in (0, 1):
            identities = []
            for port in (2, 3, 4):
                with self.subTest(direction=direction, port=port):
                    p = self.source(direction, port)
                    self.assertFalse(p.dropped)
                    self.assertEqual(p.fields['standard_metadata', 'egress_port'], port)
                    raw = p.deparse()
                    packet = decode(raw)
                    self.assertEqual((packet.direction, packet.mode), (direction, port - 1))
                    self.assertEqual(packet.inner, self.original(direction)[14:58])
                    identities.append((packet.sequence, packet.crc, packet.inner))
                    expected = {'ethernet', 'poly', 'inner_ipv4', 'udp', 'protected_data'}
                    expected |= {2: {'ipv4'}, 3: {'ipv6'},
                                 4: {'srcRoutes[0]', 'srcRoutes[1]', 'srcRoutes[2]'}}[port]
                    self.assertEqual(p.valid, expected)
                    self.assertEqual(p.registers, [1, 0] if direction == 0 else [0, 1])
                    if port == 2:
                        self.assertEqual(p.fields['ipv4', 'totalLen'], 78)
                        self.assertEqual(checksum(raw[14:34]), 0)
                    elif port == 3:
                        self.assertEqual(p.fields['ipv6', 'payLoadLen'], 58)
                    else:
                        self.assertEqual(packet.stack, (2, 2, 1) if direction == 0 else (1, 1, 1))
                        self.assertEqual([p.fields[f'srcRoutes[{i}]', 'bos'] for i in range(3)], [0, 0, 1])
            self.assertEqual(identities, [identities[0]] * 3)

    def test_invalid_exit_instance_direction_and_incomplete_headers(self):
        for port in (0, 1, 5, 511):
            self.assertTrue(self.source(0, port).dropped)
        for header in ('poly', 'inner_ipv4', 'udp', 'protected_data'):
            p = self.node(self.original(), 's1').pipeline('ingress')
            p.valid.discard(header)
            self.assertTrue(p.egress(2, replication=True).dropped)
        p = self.node(self.original(), 's1').pipeline('ingress')
        self.assertTrue(p.egress(2, replication=False).dropped)
        p = self.node(self.original(), 's1').pipeline('ingress')
        p.fields['poly', 'direction'] = 2
        self.assertTrue(p.egress(2, replication=True).dropped)
        p = self.node(self.original(), 's1').pipeline('ingress')
        p.valid.update({'ipv6', 'srcRoutes[8]'})
        p.egress(4, replication=True)
        self.assertNotIn('ipv6', p.valid)
        self.assertNotIn('srcRoutes[8]', p.valid)

    def trace(self, direction, mode):
        source = 's1' if direction == 0 else 's2'
        destination = 's2' if direction == 0 else 's1'
        first, second = {1: ('s11', 's12'), 2: ('s21', 's22'), 3: ('s31', 's32')}[mode]
        if direction:
            first, second = second, first
        p = self.source(direction, mode + 1)
        frames = [p.deparse()]
        port_in, port_out = (1, 2) if direction == 0 else (2, 1)
        for name in (first, second):
            frames.append(frames[-1])
            p = self.node(frames[-1], name, port_in).pipeline('ingress')
            self.assertFalse(p.dropped)
            self.assertEqual(p.fields['standard_metadata', 'mcast_grp'], 0)
            self.assertEqual(p.fields['standard_metadata', 'egress_spec'], port_out)
            frames.append(p.egress().deparse())
        frames.append(frames[-1])
        p = self.node(frames[-1], destination, mode + 1).pipeline('ingress')
        self.assertTrue(p.dropped)
        self.assertIn('MyIngress.polymorphic_destination', p.visited)
        self.assertNotIn('tbl_srcRoute_finish', p.visited)
        if mode == 3:
            self.assertIn('srcRoutes[0]', p.valid)
            self.assertNotIn('srcRoutes[1]', p.valid)
            self.assertEqual(p.fields['ethernet', 'etherType'], 0x1234)
        return frames

    def test_six_multi_hop_paths_and_gateway_interception(self):
        for direction in (0, 1):
            for mode in (1, 2, 3):
                with self.subTest(direction=direction, mode=mode):
                    packets = [decode(f) for f in self.trace(direction, mode)]
                    self.assertEqual({p.sequence for p in packets}, {1})
                    self.assertEqual(len({p.inner for p in packets}), 1)
                    if mode in (1, 2):
                        self.assertEqual([p.lifetime for p in packets], [64, 64, 63, 63, 62, 62])
                    else:
                        self.assertEqual([len(p.stack) for p in packets], [3, 3, 2, 2, 1, 1])

    def test_missing_destination_rules_fail_closed(self):
        destination_id = self.helper.get_tables_id('MyIngress.polymorphic_destination')
        for direction in (0, 1):
            name = 's2' if direction == 0 else 's1'
            entries = [e for e in self.entries[name] if e.table_id != destination_id or e.is_default_action]
            for mode in (1, 2, 3):
                frame = self.trace(direction, mode)[-1]
                p = self.node(frame, name, mode + 1, entries).pipeline('ingress')
                self.assertTrue(p.dropped)

    def test_ordinary_forwarding_and_sr_distinction(self):
        for direction in (0, 1):
            names = ['s1', 's11', 's12', 's2'] if direction == 0 else ['s2', 's12', 's11', 's1']
            wire = bytearray(self.original(direction))
            # Ordinary non-5000 UDP; keep a consistent inner IPv4 checksum.
            wire[36:38] = (4321).to_bytes(2, 'big')
            for name in names:
                p = self.node(bytes(wire), name, 1 if direction == 0 else 2).pipeline('ingress')
                self.assertFalse(p.dropped)
                self.assertNotIn('MyIngress.polymorphic_destination', p.visited)
                p.egress()
                self.assertEqual(p.fields['scalars', 'metadata.scheduled'], 0)
                self.assertNotIn('poly', p.valid)
                wire = p.deparse()
            self.assertEqual(p.fields['standard_metadata', 'egress_spec'], 1)
            self.assertEqual(p.fields['ipv4', 'ttl'], 60)
            # Ordinary SR includes the source gateway's own first output port.
            payload = bytes(self.original(direction)[14:])
            route = (4, 2, 2, 1) if direction == 0 else (4, 1, 1, 1)
            wire = ethernet(0x1234, b''.join(struct.pack('!H', port | (0x8000 if i == 3 else 0))
                                           for i, port in enumerate(route)) + payload)
            sr_names = ['s1', 's31', 's32', 's2'] if direction == 0 else ['s2', 's32', 's31', 's1']
            for name in sr_names:
                p = self.node(wire, name).pipeline('ingress').egress()
                self.assertFalse(p.dropped)
                self.assertNotIn('poly', p.valid)
                wire = p.deparse()
            self.assertEqual(wire[12:14], b'\x08\x00')
            self.assertEqual(p.fields['standard_metadata', 'egress_spec'], 1)
            # Ordinary IPv6 keeps its payload and does not acquire PolyShim.
            src, dst = ('1234', '5678') if direction == 0 else ('5678', '1234')
            wire = bytearray(ethernet(0x86dd, ipv6(17, udp(4321))))
            wire[22:54] = ipaddress.ip_address('fe80::' + src).packed + ipaddress.ip_address('fe80::' + dst).packed
            names = ['s1', 's21', 's22', 's2'] if direction == 0 else ['s2', 's22', 's21', 's1']
            for name in names:
                p = self.node(bytes(wire), name).pipeline('ingress').egress()
                self.assertFalse(p.dropped)
                self.assertNotIn('poly', p.valid)
                wire = p.deparse()
            self.assertEqual(p.fields['ipv6', 'hopLimit'], 60)
            self.assertEqual(wire[54:], udp(4321))

    def test_ordinary_arp_reply(self):
        for name, source_ip, target_ip in (('s1', 0x0a000101, 0x0a00010a),
                                           ('s2', 0x0a000202, 0x0a000214)):
            arp = struct.pack('!HHBBH6sI6sI', 1, 0x0800, 6, 4, 1,
                              bytes.fromhex('080000000101'), source_ip, bytes(6), target_ip)
            p = self.node(ethernet(0x0806, arp), name).pipeline('ingress').egress()
            self.assertFalse(p.dropped)
            self.assertEqual(p.fields['arp', 'oper'], 2)
            self.assertEqual(p.fields['standard_metadata', 'egress_spec'], 1)
            self.assertEqual(p.valid, {'ethernet', 'arp'})

    def test_pcap_checker_with_synthetic_full_path_fixtures(self):
        header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        def write(path, frames):
            path.write_bytes(header + b''.join(
                struct.pack('<IIII', 0, i, len(frame), len(frame)) + frame
                for i, frame in enumerate(frames)))
        # These temporary Python-produced files are NOT runtime evidence.
        for direction in (0, 1):
            with tempfile.TemporaryDirectory() as temporary:
                folder = Path(temporary)
                source, destination = ('s1', 's2') if direction == 0 else ('s2', 's1')
                original = self.original(direction)
                write(folder / f'{source}-eth1_in.pcap', [original])
                write(folder / f'{destination}-eth1_out.pcap', [])
                trace = {}
                for mode in (1, 2, 3):
                    for name, frame in zip(path_points(direction, mode), self.trace(direction, mode)):
                        trace[name] = frame
                        write(folder / name, [frame])
                self.assertEqual(check_pcaps(folder, direction, 1, 'source'),
                                 check_pcaps(folder, direction, 1, 'full'))
                middle = path_points(direction, 1)[3]
                write(folder / middle, [])
                with self.assertRaisesRegex(ValueError, 'expected 1 distinct copies'):
                    check_pcaps(folder, direction)
                write(folder / middle, [trace[middle]])
                write(folder / f'{destination}-eth1_out.pcap', [original])
                with self.assertRaisesRegex(ValueError, 'unexpected restored'):
                    check_pcaps(folder, direction)
                write(folder / f'{destination}-eth1_out.pcap', [])
                filename = path_points(direction, 1)[0]
                malformed = bytearray(trace[filename])
                malformed[24] ^= 1  # outer IPv4 checksum byte
                write(folder / filename, [bytes(malformed)])
                with self.assertRaisesRegex(ValueError, 'checksum'):
                    check_pcaps(folder, direction)

    def test_destination_configuration_and_m3_source_preservation(self):
        table = self.helper.get('tables', name='MyIngress.polymorphic_destination')
        self.assertEqual([(f.name, f.bitwidth) for f in table.match_fields],
                         [('standard_metadata.ingress_port', 9), ('hdr.poly.direction', 8), ('hdr.poly.modality_id', 8)])
        for name, entries in self.entries.items():
            destinations = [e for e in entries if e.table_id == table.preamble.id]
            if name not in ('s1', 's2'):
                self.assertEqual(destinations, [])
                continue
            self.assertEqual(sum(e.is_default_action for e in destinations), 1)
            actual = {tuple(int.from_bytes(f.exact.value, 'big') for f in e.match)
                      for e in destinations if not e.is_default_action}
            direction = int(name == 's1')
            self.assertEqual(actual, {(2, direction, 1), (3, direction, 2), (4, direction, 3)})
            for entry in destinations:
                self.assertEqual(self.helper.get_actions_name(entry.action.action.action_id), 'MyIngress.hold_polymorphic')
        old = subprocess.check_output(['git', '--git-dir=.course-git', '--work-tree=.', 'show',
                                       'd7284f6:polymorphic.p4'], cwd=ROOT, text=True)
        new = (ROOT / 'polymorphic.p4').read_text()
        for start, end in [('register<bit<32>>(2) sequence_register;', '    action srcRoute_nhop()'),
                           ('// M3: fixed Ethernet/IPv4/UDP input only', '// TODO M5:')]:
            a, b = old[old.index(start):], new[new.index(start):]
            # Destination table is inserted after prepare_polymorphic only.
            if start.startswith('register'):
                a = a[:a.index(end)]
                b = b[:b.index('    // M4 landing point')]
            else:
                a, b = a[:a.index(end)], b[:b.index(end)]
            self.assertEqual(a.rstrip(), b.rstrip())


if __name__ == '__main__':
    print('OFFLINE ONLY: JSON interpretation, Python checksum model and synthetic hop traces.', flush=True)
    unittest.main(verbosity=2)
