#!/usr/bin/env python3
"""OFFLINE ONLY: execute p4c JSON actions with Python CRC/register/counter models.

This tests actual compiled instructions and actual controller protobufs, not a
handwritten replacement voting state machine. Archived M4 packet replay is
also OFFLINE, and is not evidence of M5 execution on BMv2.
"""
from collections import Counter
import copy
from contextlib import redirect_stdout
import importlib.util
import io
import itertools
import json
from pathlib import Path
import struct
import unittest
import zlib

import check_m4 as m4
from check_m2_parser import ethernet, ipv4, ipv6, udp
from check_m3_pcaps import read_pcap
from p4.v1 import p4runtime_pb2
from p4.config.v1 import p4info_pb2
from p4runtime_lib.switch import SwitchConnection

ROOT = m4.ROOT


def inner_packet(direction, data):
    raw = bytearray(ipv4(17, udp(data=data.ljust(16, b'\0'))))
    if direction:
        raw[12:20] = raw[16:20] + raw[12:16]
        raw[10:12] = bytes(2)
        raw[10:12] = struct.pack('!H', m4.checksum(bytes(raw[:20])))
    return bytes(raw)


def crc_input(inner):
    return inner[12:20] + inner[9:10] + inner[20:24] + inner[28:44]


def copy_packet(sequence, mode, data=b'A', direction=0, source_crc=0xdeadbeef):
    inner = inner_packet(direction, data)
    shim = struct.pack('!HBIBIH', 0x504f, direction, sequence, mode, source_crc, 0x0800)
    if mode == 1:
        outer = bytearray(ipv4(253, shim + inner))
        if direction:
            outer[12:20] = outer[16:20] + outer[12:16]
            outer[10:12] = bytes(2)
            outer[10:12] = struct.pack('!H', m4.checksum(bytes(outer[:20])))
        return ethernet(0x0800, bytes(outer))
    if mode == 2:
        outer = bytearray(ipv6(253, shim + inner))
        if direction:
            outer[8:40] = outer[24:40] + outer[8:24]
        return ethernet(0x86dd, bytes(outer))
    return ethernet(0x1234, struct.pack('!H', 0x8001) + shim + inner)


class Session:
    def __init__(self, test, direction=0, name=None, entries=None):
        self.test, self.direction = test, direction
        self.name = name if name else ('s2' if direction == 0 else 's1')
        self.entries = test.entries[self.name] if entries is None else entries
        self.state = None
        self.accepts = []

    def send(self, sequence=1, mode=1, data=b'A', wire=None, port=None, **kwargs):
        wire = copy_packet(sequence, mode, data, self.direction, **kwargs) if wire is None else wire
        p = m4.OfflineSwitch(self.test.program, wire, self.test.helper, self.entries,
                             port=mode + 1 if port is None else port, state=self.state)
        p.pipeline('ingress')
        self.state = p.state
        self.accepts.append(p.fields['scalars', 'metadata.adjudication_accept'])
        return p

    def reg(self, name, sequence=1):
        return self.state['registers']['MyIngress.' + name][sequence & 1023]

    def stats(self):
        counts = self.state['counters']
        self.test.assertEqual([counts['MyIngress.' + name][i]
                               for name in ('good_count', 'bad_count') for i in (0, 4)], [0, 0, 0, 0])
        return (counts['MyIngress.good_count'][1:4], counts['MyIngress.bad_count'][1:4],
                counts['MyIngress.no_majority_count'][0])


class M5Checks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.program = json.loads((ROOT / 'build/polymorphic.json').read_text())
        cls.helper = m4.P4InfoHelper(str(ROOT / 'build/polymorphic.p4.p4info.txtpb'))
        cls.entries = m4.controller_entries(cls.helper)

    def assert_safe(self, packet):
        self.assertTrue(packet.dropped)
        self.assertEqual(packet.fields['standard_metadata', 'egress_spec'], 511)
        self.assertIn('poly', packet.valid)
        self.assertIn('inner_ipv4', packet.valid)
        self.assertNotIn('tbl_srcRoute_finish', packet.visited)

    def test_AAA_AAB_ABB_ABC_and_missing_mode(self):
        cases = [((b'A', b'A', b'A'), [0, 1, 0], ([1, 1, 1], [0, 0, 0], 0), 1),
                 ((b'A', b'A', b'B'), [0, 1, 0], ([1, 1, 0], [0, 0, 1], 0), 1),
                 ((b'A', b'B', b'B'), [0, 0, 1], ([0, 1, 1], [1, 0, 0], 0), 1),
                 ((b'A', b'B', b'C'), [0, 0, 0], ([0, 0, 0], [0, 0, 0], 1), 2)]
        for data, accepts, stats, status in cases:
            with self.subTest(data=data):
                session = Session(self)
                for mode, value in enumerate(data, 1):
                    self.assert_safe(session.send(mode=mode, data=value))
                self.assertEqual(session.accepts, accepts)
                self.assertEqual(session.stats(), stats)
                self.assertEqual(session.reg('decision_status'), status)
                self.assertEqual(session.reg('decided'), 1)
                self.assertEqual(session.reg('seen_modes'), 7)
        missing = Session(self)
        missing.send(mode=1)
        missing.send(mode=3)
        self.assertEqual(missing.accepts, [0, 1])
        self.assertEqual(missing.stats(), ([1, 0, 1], [0, 0, 0], 0))

    def test_duplicate_cannot_vote_or_pollute_state(self):
        session = Session(self)
        session.send(mode=1)
        snapshot = copy.deepcopy(session.state)
        session.send(mode=1, data=b'B')
        self.assertEqual(session.state, snapshot)
        session.send(mode=2, data=b'B')
        self.assertEqual(session.accepts, [0, 0, 0])
        self.assertEqual(session.reg('candidate_counts'), 2)
        self.assertEqual(session.reg('seen_modes'), 3)
        self.assertEqual(session.stats(), ([0, 0, 0], [0, 0, 0], 0))
        session.send(mode=3, data=b'B')
        self.assertEqual(session.stats(), ([0, 1, 1], [1, 0, 0], 0))
        self.assertEqual(session.accepts[-1], 1)
        snapshot = copy.deepcopy(session.state)
        for _ in range(3):
            for mode in (1, 2, 3):
                session.send(mode=mode, data=b'C')
        self.assertEqual(session.state, snapshot)
        self.assertEqual(sum(session.accepts), 1)

    def test_all_arrival_orders_and_mode1_corruption(self):
        for order in itertools.permutations((1, 2, 3)):
            for values in ((b'A', b'A', b'A'), (b'B', b'A', b'A'),
                           (b'A', b'B', b'B'), (b'A', b'B', b'C')):
                with self.subTest(order=order, values=values):
                    session = Session(self)
                    for mode in order:
                        self.assert_safe(session.send(mode=mode, data=values[mode - 1]))
                    winners = [value for value, count in Counter(values).items() if count >= 2]
                    winner = winners[0] if winners else None
                    self.assertEqual(sum(session.accepts), int(winner is not None))
                    good = [int(v == winner) for v in values] if winner else [0, 0, 0]
                    bad = [int(v != winner) for v in values] if winner else [0, 0, 0]
                    self.assertEqual(session.stats(), (good, bad, int(winner is None)))

    def test_late_third_and_no_majority_exactly_once(self):
        session = Session(self)
        session.send(mode=3)
        session.send(mode=1)
        self.assertEqual(session.stats(), ([1, 0, 1], [0, 0, 0], 0))
        session.send(mode=2, data=b'B')
        self.assertEqual(session.accepts, [0, 1, 0])
        self.assertEqual(session.stats(), ([1, 0, 1], [0, 1, 0], 0))
        no = Session(self)
        for mode, data in ((1, b'A'), (2, b'B'), (3, b'C')):
            no.send(mode=mode, data=data)
        before = copy.deepcopy(no.state)
        for _ in range(5):
            for mode in (1, 2, 3):
                no.send(mode=mode)
        self.assertEqual(no.state, before)
        self.assertEqual(no.stats()[2], 1)

    def test_interleaved_sequences(self):
        session = Session(self)
        for seq, mode, data in ((1, 2, b'A'), (2, 1, b'B'), (1, 3, b'A'),
                                (2, 2, b'B'), (1, 1, b'A'), (2, 3, b'B')):
            session.send(sequence=seq, mode=mode, data=data)
        self.assertEqual(sum(session.accepts), 2)
        self.assertEqual(session.stats(), ([2, 2, 2], [0, 0, 0], 0))
        for seq in (1, 2):
            self.assertEqual(session.reg('seq_tag', seq), seq)
            self.assertEqual(session.reg('decision_status', seq), 1)

    def test_window_reuse_rejects_old_colliding_packet(self):
        session = Session(self)
        for seq, data in ((1, b'A'), (1025, b'B')):
            for mode in (1, 2):
                session.send(sequence=seq, mode=mode, data=data)
        self.assertEqual(session.reg('seq_tag'), 1025)
        before = copy.deepcopy(session.state)
        for mode in (1, 2, 3):
            session.send(sequence=1, mode=mode, data=b'C')
        self.assertEqual(session.state, before)
        session.send(sequence=1025, mode=3, data=b'B')
        self.assertEqual(sum(session.accepts), 2)
        self.assertEqual(session.stats(), ([2, 2, 1], [0, 0, 0], 0))

    def test_continuous_stream_exceeds_window(self):
        session = Session(self)
        for sequence in range(1, 1031):
            session.send(sequence=sequence, mode=1)
            session.send(sequence=sequence, mode=2)
            if sequence % 10 == 0:
                session.send(sequence=sequence, mode=3)
        self.assertEqual(sum(session.accepts), 1030)
        self.assertEqual(session.stats(), ([1030, 1030, 103], [0, 0, 0], 0))
        before = copy.deepcopy(session.state)
        session.send(sequence=1, mode=3)
        self.assertEqual(session.state, before)

    def test_window_boundary_empty_old_slot_and_half_range(self):
        session = Session(self)
        session.send(sequence=2000)
        session.send(sequence=977)
        self.assertEqual(session.reg('slot_valid', 977), 1)  # age 1023 is inside
        before = copy.deepcopy(session.state)
        session.send(sequence=976)  # age 1024, even though the slot is empty
        session.send(sequence=(2000 + 0x80000000) & 0xffffffff)
        self.assertEqual(session.state, before)
        self.assertEqual(session.state['registers']['MyIngress.latest_sequence'][0], 2000)

    def test_sequence_wrap_zero_and_wrapped_collision(self):
        session = Session(self)
        for seq in (0xfffffffe, 0xffffffff, 0, 1):
            for mode in (1, 2):
                session.send(sequence=seq, mode=mode)
            self.assertEqual(session.reg('seq_tag', seq), seq)
            self.assertEqual(session.reg('slot_valid', seq), 1)
        self.assertEqual(sum(session.accepts), 4)
        self.assertEqual(session.state['registers']['MyIngress.latest_sequence'][0], 1)
        session.send(sequence=0xfffffffe, mode=3)  # valid late third across wrap
        self.assertEqual(session.stats(), ([4, 4, 1], [0, 0, 0], 0))
        another = Session(self)
        another.send(sequence=0xffffffff)
        another.send(sequence=1023, data=b'B')  # newer by 1024, same slot
        before = copy.deepcopy(another.state)
        another.send(sequence=0xffffffff, mode=2)
        self.assertEqual(another.state, before)
        self.assertEqual(another.reg('seq_tag', 1023), 1023)

    def test_direction_isolation_and_role_matching(self):
        forward, reverse = Session(self), Session(self, 1)
        for mode in (1, 2, 3):
            forward.send(mode=mode)
            reverse.send(mode=mode, data=b'B')
        self.assertEqual(forward.stats(), reverse.stats())
        self.assertEqual(forward.stats(), ([1, 1, 1], [0, 0, 0], 0))
        self.assertNotEqual(forward.reg('decided_crc'), reverse.reg('decided_crc'))
        for name, port in (('s1', 2), ('s2', 3)):
            wrong = Session(self, name=name)
            p = wrong.send(mode=1, port=port)
            self.assert_safe(p)
            self.assertFalse(any(wrong.state['registers']['MyIngress.slot_valid']))
        middle = Session(self, name='s11')
        p = middle.send(mode=1, port=1)
        self.assertFalse(p.dropped)
        self.assertFalse(any(middle.state['registers']['MyIngress.slot_valid']))

    def test_ordinary_protocols_leave_vote_state_unchanged(self):
        session = Session(self)
        session.send(mode=1)
        session.send(mode=2)
        before = copy.deepcopy(session.state)
        inputs = [(ethernet(0x0800, ipv4(1, bytes(32))), 2),
                  (ethernet(0x86dd, ipv6(58, bytes(32))), 3),
                  (ethernet(0x1234, struct.pack('!H', 0x8001) + ipv4(17, udp(4321))), 4)]
        for wire, port in inputs:
            p = m4.OfflineSwitch(self.program, wire, self.helper, self.entries['s2'],
                                 port=port, state=session.state)
            p.fields['scalars', 'metadata.adjudication_accept'] = 1
            p.pipeline('ingress').egress()
            self.assertFalse(p.dropped)
            self.assertEqual(p.fields['standard_metadata', 'egress_spec'], 1)
            self.assertEqual(p.fields['scalars', 'metadata.adjudication_accept'], 0)
            self.assertEqual(p.hash_inputs, [])
            self.assertEqual(p.state, before)

    def test_observed_crc_order_source_independence_and_tampering(self):
        session = Session(self)
        for mode, source in ((1, 0), (2, 0xffffffff), (3, 0xdeadbeef)):
            p = session.send(mode=mode, source_crc=source)
            raw = crc_input(inner_packet(0, b'A'))
            self.assertEqual(len(raw), 29)
            self.assertEqual(p.hash_inputs, [raw])
            self.assertEqual(p.fields['scalars', 'metadata.vote_observed_crc'], zlib.crc32(raw))
        self.assertEqual(session.stats(), ([1, 1, 1], [0, 0, 0], 0))
        altered = Session(self)
        source = zlib.crc32(crc_input(inner_packet(0, b'A')))
        for mode, data in ((1, b'B'), (2, b'A'), (3, b'A')):
            altered.send(mode=mode, data=data, source_crc=source)
        self.assertEqual(altered.stats(), ([0, 1, 1], [1, 0, 0], 0))
        self.assertEqual(altered.reg('decided_crc'), source)
        # Alter outer addresses/TTL and Ethernet MAC; those are excluded.
        wire = bytearray(copy_packet(1, 1))
        wire[:12] = bytes(12)
        wire[22] = 31
        wire[26:34] = bytes(8)
        p = Session(self).send(wire=bytes(wire))
        self.assertEqual(p.hash_inputs, [raw])

    def test_compiled_atomic_action_and_interfaces(self):
        actions = [a for a in self.program['actions'] if a['name'] == 'MyIngress.adjudicate_polymorphic']
        self.assertEqual(len(actions), 1)
        action = actions[0]
        self.assertTrue(any(p['op'] == '_jump_if_zero' for p in action['primitives']))
        locked = {p['value'] for q in action['primitives'] for p in q['parameters'] if p['type'] == 'register_array'}
        self.assertEqual(len(locked), 14)
        for other in self.program['actions']:
            if other['id'] == action['id']:
                continue
            used = {p['value'] for q in other['primitives'] for p in q['parameters'] if p['type'] == 'register_array'}
            self.assertFalse(locked & used)
        text = (ROOT / 'polymorphic.p4').read_text().split('action adjudicate_polymorphic()', 1)[1].split('    action hold_polymorphic()', 1)[0]
        self.assertIn('@atomic', text)
        self.assertNotIn('hdr.poly.source_crc32', text)
        for name, size in (('good_count', 5), ('bad_count', 5), ('no_majority_count', 1)):
            counter = self.helper.get('counters', name='MyIngress.' + name)
            self.assertEqual(counter.size, size)
            self.assertEqual(counter.spec.unit, p4info_pb2.CounterSpec.PACKETS)

    def test_official_counter_read_and_feedback_without_socket(self):
        def load(name, filename):
            spec = importlib.util.spec_from_file_location(name, ROOT / filename)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
        reader = load('course_reader', 'read-counters.py')
        feedback = load('course_feedback', 'evaluate-counters.py')
        session = Session(self)
        session.send(mode=1)
        session.send(mode=3)
        helper = self.helper
        test = self
        class Stub:
            def Read(self, request):
                test.assertEqual(request.device_id, 1)
                test.assertEqual(len(request.entities), 1)
                entry = request.entities[0].counter_entry
                response = p4runtime_pb2.ReadResponse()
                out = response.entities.add().counter_entry
                out.CopyFrom(entry)
                name = helper.get_counters_name(entry.counter_id)
                out.data.packet_count = session.state['counters'][name][entry.index.index]
                return iter([response])
        sw = SwitchConnection.__new__(SwitchConnection)
        sw.device_id, sw.client_stub = 1, Stub()
        values = [reader.read_counter(sw, helper, 'MyIngress.good_count', i) for i in (1, 2, 3)]
        self.assertEqual(values, [1, 0, 1])
        out = io.StringIO()
        with redirect_stdout(out):
            feedback.evaluate('s2 mode1_good=1 mode1_bad=0 mode2_good=0 mode2_bad=0 mode3_good=1 mode3_bad=0 no_majority=0')
        self.assertIn('mode2 status=NO_DATA', out.getvalue())

    def test_archived_real_M4_arrivals_replayed_OFFLINE(self):
        for direction, expected in ((0, 2), (1, 1)):
            session = Session(self, direction)
            for mode in (1, 2, 3):
                path = ROOT / 'evidence/m4-runtime' / f'{session.name}-eth{mode + 1}_in.pcap'
                for wire in read_pcap(path):
                    decoded = m4.decode(wire)
                    if decoded and decoded.direction == direction:
                        p = session.send(mode=mode, wire=wire)
                        self.assert_safe(p)
                        self.assertEqual(p.fields['scalars', 'metadata.vote_observed_crc'], decoded.crc)
            self.assertEqual(sum(session.accepts), expected)
            self.assertEqual(session.stats(), ([expected] * 3, [0, 0, 0], 0))


if __name__ == '__main__':
    print('OFFLINE ONLY: compiled JSON instructions; Python CRC/register/counter models. NOT BMv2 M5 execution.', flush=True)
    unittest.main(verbosity=2)
