#!/usr/bin/env python3
"""OFFLINE ONLY: compiled JSON execution, modeled externs and synthetic fixtures.

Never launches BMv2/Mininet. Archived native M5 inputs are replayed OFFLINE;
temporary synthetic pcaps test the checker and are not runtime evidence.
"""
import ast
from collections import Counter, defaultdict
import copy
import itertools
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

import check_m4 as m4
import check_m5 as m5
from check_m3_pcaps import read_pcap
from check_m6_pcaps import check as check_pcaps, normalized_inner

ROOT = m4.ROOT


def write_synthetic_pcap(path, frames):
    with path.open('wb') as stream:
        stream.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for frame in frames:
            stream.write(struct.pack('<IIII', 0, 0, len(frame), len(frame)) + frame)


class M6Checks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.program = json.loads((ROOT / 'build/polymorphic.json').read_text())
        cls.helper = m4.P4InfoHelper(str(ROOT / 'build/polymorphic.p4.p4info.txtpb'))
        cls.entries = m4.controller_entries(cls.helper)

    def result(self, packet, inner, direction):
        self.assertEqual(packet.fields['scalars', 'metadata.adjudication_accept'], 1)
        self.assertFalse(packet.dropped)
        self.assertEqual(packet.valid, {'ethernet', 'ipv4', 'udp', 'protected_data'})
        self.assertEqual(packet.fields['standard_metadata', 'egress_spec'], 1)
        self.assertEqual(packet.fields['standard_metadata', 'mcast_grp'], 0)
        self.assertEqual(packet.fields['scalars', 'metadata.scheduled'], 0)
        for route in ('MyIngress.polymorphic_schedule', 'MyIngress.ipv4_lpm',
                      'MyIngress.ipv6_lpm', 'tbl_srcRoute_nhop', 'tbl_srcRoute_finish'):
            self.assertNotIn(route, packet.visited)
        wire = packet.egress().deparse()
        prefix = bytes.fromhex('0800000002020800000002000800' if direction == 0
                               else '0800000001010800000001000800')
        self.assertEqual(wire, prefix + normalized_inner(inner))
        self.assertEqual(m4.checksum(wire[14:34]), 0)
        self.assertIsNone(m4.decode(wire))
        return wire

    def held(self, packet):
        self.assertTrue(packet.dropped)
        self.assertEqual(packet.fields['standard_metadata', 'egress_spec'], 511)
        self.assertEqual(packet.fields['scalars', 'metadata.adjudication_accept'], 0)
        self.assertIn('poly', packet.valid)
        self.assertIn('inner_ipv4', packet.valid)

    def test_all_six_arrival_orders_both_directions_and_all_winning_modes(self):
        winners = set()
        for direction in (0, 1):
            for order in itertools.permutations((1, 2, 3)):
                session = m5.Session(self, direction)
                outputs = []
                for mode in order:
                    p = session.send(mode=mode)
                    if p.fields['scalars', 'metadata.adjudication_accept']:
                        outputs.append(self.result(p, m5.inner_packet(direction, b'A'), direction))
                        winners.add((direction, mode))
                    else:
                        self.held(p)
                self.assertEqual(len(outputs), 1)
                self.assertEqual(session.stats(), ([1, 1, 1], [0, 0, 0], 0))
        self.assertEqual(winners, set(itertools.product((0, 1), (1, 2, 3))))

    def test_AAB_ABB_outputs_the_majority_content(self):
        for direction in (0, 1):
            for data in ((b'A', b'A', b'B'), (b'A', b'B', b'B')):
                winner = Counter(data).most_common(1)[0][0]
                for order in itertools.permutations((1, 2, 3)):
                    session = m5.Session(self, direction)
                    outputs = []
                    for mode in order:
                        p = session.send(mode=mode, data=data[mode - 1])
                        if p.dropped:
                            self.held(p)
                        else:
                            outputs.append(self.result(p, m5.inner_packet(direction, winner), direction))
                    self.assertEqual(len(outputs), 1)
                    self.assertEqual(session.stats(), ([int(x == winner) for x in data],
                                                       [int(x != winner) for x in data], 0))

    def test_no_majority_and_repeated_modes_never_output(self):
        for direction in (0, 1):
            session = m5.Session(self, direction)
            for mode, data in ((3, b'C'), (1, b'A'), (2, b'B')):
                self.held(session.send(mode=mode, data=data))
            snapshot = copy.deepcopy(session.state)
            for _ in range(3):
                for mode in (1, 2, 3):
                    self.held(session.send(mode=mode))
            self.assertEqual(session.state, snapshot)
            self.assertEqual(session.stats(), ([0, 0, 0], [0, 0, 0], 1))

    def test_two_equal_modes_output_without_the_third(self):
        for direction in (0, 1):
            for first, second in itertools.permutations((1, 2, 3), 2):
                session = m5.Session(self, direction)
                self.held(session.send(mode=first))
                self.result(session.send(mode=second), m5.inner_packet(direction, b'A'), direction)
                self.assertEqual(session.stats(), ([int(m in (first, second)) for m in (1, 2, 3)],
                                                   [0, 0, 0], 0))

    def test_duplicate_before_and_after_decision_does_not_output_twice(self):
        session = m5.Session(self)
        self.held(session.send(mode=3))
        before = copy.deepcopy(session.state)
        self.held(session.send(mode=3, data=b'changed'))
        self.assertEqual(session.state, before)
        self.held(session.send(mode=1, data=b'B'))
        self.result(session.send(mode=2, data=b'B'), m5.inner_packet(0, b'B'), 0)
        before = copy.deepcopy(session.state)
        for mode in (1, 2, 3, 2, 1, 3):
            self.held(session.send(mode=mode, data=b'new'))
        self.assertEqual(session.state, before)
        self.assertEqual(sum(session.accepts), 1)
        self.assertEqual(session.stats(), ([1, 1, 0], [0, 0, 1], 0))

    def test_late_third_only_updates_statistics(self):
        for third in (b'A', b'B'):
            session = m5.Session(self)
            self.held(session.send(mode=2))
            self.result(session.send(mode=1), m5.inner_packet(0, b'A'), 0)
            winner = session.reg('decided_crc')
            self.held(session.send(mode=3, data=third))
            self.assertEqual(session.reg('decided_crc'), winner)
            self.assertEqual(session.stats(), ([1, 1, int(third == b'A')],
                                               [0, 0, int(third != b'A')], 0))
            self.assertEqual(sum(session.accepts), 1)

    def test_inner_fields_udp_checksum_and_binary_payload_preserved(self):
        for direction, winner in itertools.product((0, 1), (1, 2, 3)):
            inner = bytearray(m5.inner_packet(direction, bytes(range(16))))
            inner[1] = 0xb8
            inner[4:8] = bytes.fromhex('abcd4000')  # identification and DF
            inner[8] = 23
            inner[20:24] = struct.pack('!HH', 54321, 5000)
            inner[26:28] = bytes(2)
            pseudo = inner[12:20] + bytes.fromhex('00110018')
            inner[26:28] = struct.pack('!H', m4.checksum(bytes(pseudo + inner[20:])))
            inner[10:12] = b'\x12\x34'  # deliberately stale IPv4 checksum
            session = m5.Session(self, direction)
            for mode in (next(m for m in (1, 2, 3) if m != winner), winner):
                wire = m5.copy_packet(1, mode, direction=direction)
                wire = wire[:-44] + bytes(inner)
                p = session.send(mode=mode, wire=wire)
            result = self.result(p, bytes(inner), direction)
            self.assertEqual(result[34:58], inner[20:44])  # UDP incl checksum and all 16 bytes
            self.assertEqual(result[22], 23)  # no accidental ordinary-route TTL decrement

    def test_sr_winner_invalidates_all_nine_stack_elements(self):
        session = m5.Session(self)
        self.held(session.send(mode=1))
        route = b''.join(struct.pack('!H', 1 | (0x8000 if i == 8 else 0)) for i in range(9))
        wire = m5.copy_packet(1, 3)
        wire = wire[:14] + route + wire[16:]
        packet = session.send(mode=3, wire=wire)
        self.result(packet, m5.inner_packet(0, b'A'), 0)
        self.assertTrue(all(f'srcRoutes[{i}]' not in packet.valid for i in range(9)))

    def test_M1_M5_architecture_and_voting_source_unchanged(self):
        old = subprocess.check_output(['git', '--git-dir=.course-git', '--work-tree=.',
                                       'show', '235c188:polymorphic.p4'], cwd=ROOT, text=True)
        new = (ROOT / 'polymorphic.p4').read_text()
        ranges = [('parser MyParser(', 'control MyVerifyChecksum('),
                  ('    register<bit<32>>(2) sequence_register;', '    action drop()'),
                  ('    action start_polymorphic(', '    action adjudicate_polymorphic()'),
                  ('    action adjudicate_polymorphic()', '    // Fail closed'),
                  ('    table polymorphic_destination', '    action srcRoute_nhop()'),
                  ('    action srcRoute_nhop()', '    apply {\n        meta.adjudication_accept'),
                  ('control MyEgress(', 'control MyComputeChecksum('),
                  ('control MyComputeChecksum(', 'control MyDeparser(')]
        for start, end in ranges:
            self.assertEqual(old.split(start, 1)[1].split(end, 1)[0],
                             new.split(start, 1)[1].split(end, 1)[0], start)
        self.assertEqual(old[old.index('control MyDeparser('):], new[new.index('control MyDeparser('):])
        old_controller = ast.parse(subprocess.check_output(
            ['git', '--git-dir=.course-git', '--work-tree=.', 'show', '235c188:mycontroller.py'],
            cwd=ROOT, text=True))
        new_controller = ast.parse((ROOT / 'mycontroller.py').read_text())
        old_functions = {f.name: f for f in old_controller.body if isinstance(f, ast.FunctionDef)}
        new_functions = {f.name: f for f in new_controller.body if isinstance(f, ast.FunctionDef)}
        for name, function in old_functions.items():
            if name != 'main':
                self.assertEqual(ast.dump(function), ast.dump(new_functions[name]), name)
        # Final-stage fault setup is allowed; every pre-existing statement in
        # the pipeline/route/role/PRE/source setup must still be identical.
        old_setup = next(n for n in old_functions['main'].body if isinstance(n, ast.Try)).body
        new_setup = next(n for n in new_functions['main'].body if isinstance(n, ast.Try)).body
        fault_calls = [n for n in new_setup if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)
                       and isinstance(n.value.func, ast.Name) and n.value.func.id == 'writeFaultRules']
        self.assertEqual(len(fault_calls), 1)
        new_setup = [n for n in new_setup if n not in fault_calls]
        self.assertEqual([ast.dump(n) for n in old_setup], [ast.dump(n) for n in new_setup])

    def network(self, direction, messages=(b'first', b'second'), order=(3, 1, 2)):
        """Execute compiled source/PRE model/paths/destination, collecting SYNTHETIC frames."""
        source_name, dest_name = ('s1', 's2') if direction == 0 else ('s2', 's1')
        captures = defaultdict(list)
        captures[f'{dest_name}-eth1_out.pcap'] = []
        state = None
        session = m5.Session(self, direction)
        for sequence, message in enumerate(messages, 1):
            original = m4.ethernet(0x0800, m5.inner_packet(direction, message))
            captures[f'{source_name}-eth1_in.pcap'].append(original)
            source = m4.OfflineSwitch(self.program, original, self.helper, self.entries[source_name], state=state)
            source.pipeline('ingress')
            state = source.state
            for mode in order:
                p = copy.deepcopy(source).egress(mode + 1, replication=True)
                wire = p.deparse()
                points = m4.path_points(direction, mode)
                captures[points[0]].append(wire)
                for index in (1, 3):
                    captures[points[index]].append(wire)
                    middle = points[index].split('-')[0]
                    p = m4.OfflineSwitch(self.program, wire, self.helper, self.entries[middle],
                                         port=1 if direction == 0 else 2)
                    p.pipeline('ingress').egress()
                    self.assertFalse(p.dropped)
                    wire = p.deparse()
                    captures[points[index + 1]].append(wire)
                captures[points[5]].append(wire)
                p = session.send(sequence=sequence, mode=mode, wire=wire)
                if not p.dropped:
                    captures[f'{dest_name}-eth1_out.pcap'].append(
                        self.result(p, original[14:58], direction))
                else:
                    self.held(p)
        self.assertEqual(state['registers']['MyIngress.sequence_register'][direction], len(messages))
        self.assertEqual(sum(session.accepts), len(messages))
        self.assertEqual(session.stats(), ([len(messages)] * 3, [0, 0, 0], 0))
        return captures

    def test_two_sequence_compiled_end_to_end_OFFLINE(self):
        for direction in (0, 1):
            self.network(direction)

    def test_archived_native_M5_inputs_restored_by_OFFLINE_interpreter(self):
        for direction, expected in ((0, 3), (1, 1)):
            session = m5.Session(self, direction)
            outputs = []
            for mode in (3, 2, 1):
                path = ROOT / 'evidence/m5-runtime' / f'{session.name}-eth{mode + 1}_in.pcap'
                for wire in read_pcap(path):
                    packet = m4.decode(wire)
                    if packet is None or packet.direction != direction:
                        continue
                    p = session.send(mode=mode, wire=wire)
                    if not p.dropped:
                        outputs.append(self.result(p, packet.inner, direction))
            self.assertEqual(len(outputs), expected)
            self.assertEqual(session.stats(), ([expected] * 3, [0, 0, 0], 0))

    def test_pcap_checker_positive_and_negative_SYNTHETIC_fixtures(self):
        for direction in (0, 1):
            captures = self.network(direction, messages=(b'pcap-test',))
            host = 's2-eth1_out.pcap' if direction == 0 else 's1-eth1_out.pcap'
            original_output = captures[host][0]
            cases = {'valid': captures}
            for name, frames in [('duplicate', [original_output] * 2), ('missing', []),
                                 ('outer-leak', [original_output, captures[m4.path_points(direction, 2)[5]][0]])]:
                c = copy.deepcopy(captures)
                c[host] = frames
                cases[name] = c
            for name, offset in [('checksum', 24), ('data', 57), ('UDP-source-port', 35),
                                 ('UDP-destination-port', 37), ('host-MAC', 0), ('gateway-MAC', 6)]:
                wire = bytearray(original_output)
                wire[offset] ^= 1
                c = copy.deepcopy(captures)
                c[host] = [bytes(wire)]
                cases[name] = c
            c = copy.deepcopy(captures)
            arrival = m4.path_points(direction, 1)[5]
            wire = bytearray(c[arrival][0])
            wire[37:41] = struct.pack('!I', 2)  # PolyShim sequence
            c[arrival] = [bytes(wire)]
            cases['different-arrival-sequence'] = c
            c = copy.deepcopy(captures)
            del c[m4.path_points(direction, 3)[2]]
            cases['missing-physical-hop'] = c
            for name, frames in cases.items():
                with self.subTest(direction=direction, case=name), tempfile.TemporaryDirectory() as temporary:
                    folder = Path(temporary)
                    for filename, data in frames.items():
                        write_synthetic_pcap(folder / filename, data)
                    if name == 'valid':
                        self.assertEqual(check_pcaps(folder, direction)[0][0], 1)
                        counters = folder / 'counters.txt'
                        dest = 's2' if direction == 0 else 's1'
                        counters.write_text(dest + ' mode1_good=1 mode1_bad=0 mode2_good=1 mode2_bad=0 '
                                            'mode3_good=1 mode3_bad=0 no_majority=0\n')
                        check_pcaps(folder, direction, counters=counters)
                        counters.write_text(counters.read_text().replace('mode2_good=1', 'mode2_good=0'))
                        with self.assertRaisesRegex(ValueError, 'counters'):
                            check_pcaps(folder, direction, counters=counters)
                    else:
                        with self.assertRaises((ValueError, OSError)):
                            check_pcaps(folder, direction)

    def test_pcap_checker_two_sequences_and_ambiguous_identical_inputs(self):
        for messages, ambiguous in (((b'one', b'two'), False), ((b'same', b'same'), True)):
            captures = self.network(0, messages=messages)
            with tempfile.TemporaryDirectory() as temporary:
                folder = Path(temporary)
                for filename, frames in captures.items():
                    write_synthetic_pcap(folder / filename, frames)
                if ambiguous:
                    with self.assertRaisesRegex(ValueError, 'ambiguous identical'):
                        check_pcaps(folder, 0, expected=2)
                else:
                    self.assertEqual([p[0] for p in check_pcaps(folder, 0, expected=2)], [1, 2])


if __name__ == '__main__':
    print('OFFLINE ONLY: compiled JSON + Python extern models; temporary SYNTHETIC checker fixtures. '
          'NOT native BMv2 M6 execution.', flush=True)
    unittest.main(verbosity=2)
