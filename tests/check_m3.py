#!/usr/bin/env python3
"""Offline M3 checks: compiled JSON interpretation and real protobuf building.

No sockets, BMv2 process or Mininet. The CRC extern and PRE are Python models;
these results must not be described as real switch execution.
"""
import copy
import ipaddress
import json
import operator
import struct
import sys
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

from check_m2_parser import OfflineParser, ParseError, ethernet, ipv4, ipv6, shim, sr, udp
from check_m3_pcaps import check as check_pcaps

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import mycontroller as controller
from p4runtime_lib.helper import P4InfoHelper
from p4runtime_lib.switch import SwitchConnection
from p4.v1 import p4runtime_pb2
from p4.config.v1 import p4info_pb2


class OfflineIngress(OfflineParser):
    """Interpret only the emitted operations used by M3; fail on unknown ones."""
    def __init__(self, program, wire, port=1, registers=None, rules=None, state=None):
        super().__init__(program, wire)
        self.widths = {(h, f[0]): f[1] for h, fs in self.layouts.items() for f in fs}
        self.fields.update({ref: 0 for ref in self.widths})
        self.fields['standard_metadata', 'ingress_port'] = port
        self.fields['standard_metadata', 'packet_length'] = len(wire)
        self.state = state if state is not None else {
            'registers': {r['name']: [0] * r['size'] for r in program['register_arrays']},
            'counters': {c['name']: [0] * c['size'] for c in program['counter_arrays']},
        }
        self.registers = registers if registers is not None else \
            self.state['registers']['MyIngress.sequence_register']
        self.state['registers']['MyIngress.sequence_register'] = self.registers
        self.rules = rules if rules is not None else {(1, 0x0a000202, 5000): 0}
        self.actions = {a['id']: a for a in program['actions']}
        self.runtime_data = []
        self.visited = []
        self.dropped = False
        self.hash_inputs = []
        try:
            self.run()
        except ParseError as exc:
            self.fields['standard_metadata', 'parser_error'] = next(
                code for code, name in self.errors.items() if name == str(exc))

    def evaluate(self, node):
        if node['type'] == 'field' and node['value'][1] == '$valid$':
            return int(node['value'][0] in self.valid)
        if node['type'] in ('runtime_data', 'local'):
            return self.runtime_data[node['value']]
        if node['type'] == 'expression':
            expr = node['value']
            if 'op' not in expr:
                return self.evaluate(expr)
            op = expr['op']
            right = self.evaluate(expr['right'])
            if op == 'not':
                return int(not right)
            operations = {'or': lambda a, b: int(bool(a) or bool(b)),
                          '!=': operator.ne, '>': operator.gt, '<': operator.lt,
                          '>=': operator.ge, '+': operator.add, '-': operator.sub,
                          '|': operator.or_, '^': operator.xor, '<<': operator.lshift}
            if op in operations:
                return int(operations[op](self.evaluate(expr['left']), right))
        return super().evaluate(node)

    def assign(self, target, value):
        ref = self.field_ref(target)
        self.fields[ref] = value & ((1 << self.widths[ref]) - 1)

    def copy_header(self, destination, source):
        for field, *_ in self.layouts[destination]:
            self.fields[destination, field] = self.fields[source, field]
        self.valid.discard(destination)
        if source in self.valid:
            self.valid.add(destination)

    def execute(self, action_id, data):
        action = self.actions[action_id]
        self.runtime_data = data
        offset, steps = 0, 0
        while offset < len(action['primitives']):
            steps += 1
            if steps > 4096:
                raise ValueError('action did not terminate')
            item = action['primitives'][offset]
            offset += 1
            op, p = item['op'], item['parameters']
            if op == '_jump':
                offset = self.evaluate(p[0])
                continue
            if op == '_jump_if_zero':
                if not self.evaluate(p[0]):
                    offset = self.evaluate(p[1])
                continue
            if op == 'exit':
                return True
            if op == 'assign':
                self.assign(p[0], self.evaluate(p[1]))
            elif op == 'assign_header':
                self.copy_header(p[0]['value'], p[1]['value'])
            elif op == 'add_header':
                self.valid.add(p[0]['value'])
            elif op == 'remove_header':
                self.valid.discard(p[0]['value'])
            elif op == 'mark_to_drop':
                self.dropped = True
                self.fields['standard_metadata', 'egress_spec'] = 511
                self.fields['standard_metadata', 'mcast_grp'] = 0
            elif op == 'register_read':
                self.assign(p[0], self.state['registers'][p[1]['value']][self.evaluate(p[2])])
            elif op == 'register_write':
                self.state['registers'][p[0]['value']][self.evaluate(p[1])] = self.evaluate(p[2])
            elif op == 'count':
                self.state['counters'][p[0]['value']][self.evaluate(p[1])] += 1
            elif op == 'modify_field_with_hash_based_offset':
                calc = next(c for c in self.program['calculations'] if c['name'] == p[2]['value'])
                if calc['algo'] != 'crc32':
                    raise ValueError(calc)
                bits, value = 0, 0
                for field in calc['input']:
                    width = self.widths[self.field_ref(field)]
                    value = (value << width) | self.evaluate(field)
                    bits += width
                if bits % 8:
                    raise ValueError('Unaligned CRC input')
                raw = value.to_bytes(bits // 8, 'big')
                self.hash_inputs.append(raw)
                maximum = self.evaluate(p[3])
                self.assign(p[0], self.evaluate(p[1]) + zlib.crc32(raw) % max(maximum, 1))
            elif op == 'pop':
                stack, count = p[0]['value'], self.evaluate(p[1])
                for index in range(self.stacks[stack]):
                    dst, src = f'{stack}[{index}]', f'{stack}[{index + count}]'
                    if index + count < self.stacks[stack]:
                        self.copy_header(dst, src)
                    else:
                        self.valid.discard(dst)
            else:
                raise ValueError(f'Unsupported action operation {op}')
        return False

    def ingress(self):
        pipeline = self.program['pipelines'][0]
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
            entry = table['default_entry']
            action_id = entry['action_id']
            data = [int(x, 16) for x in entry['action_data']]
            hit = False
            if node == 'MyIngress.polymorphic_schedule':
                key = tuple(self.fields[tuple(k['target'])] for k in table['key'])
                if key in self.rules:
                    hit = True
                    action_id = next(i for i in table['action_ids']
                                     if self.actions[i]['name'] == 'MyIngress.start_polymorphic')
                    data = [self.rules[key]]
            if self.execute(action_id, data):
                return self
            # M4 adds a table.apply().hit branch. BMv2 JSON represents its
            # successors with __HIT__/__MISS__ rather than action names.
            successors = table['next_tables']
            node = successors['__HIT__' if hit else '__MISS__'] if '__HIT__' in successors \
                else successors[self.actions[action_id]['name']]
        raise ValueError('Ingress did not terminate')


class RecordingSwitch(SwitchConnection):
    """Use the real WriteTableEntry/WritePREEntry methods without a channel."""
    def __init__(self, name, address, device_id, **_):
        self.name, self.device_id = name, device_id
        self.requests = []
        self.client_stub = self

    def Write(self, request):
        self.requests.append(copy.deepcopy(request))

    def MasterArbitrationUpdate(self):
        pass

    def SetForwardingPipelineConfig(self, **_):
        pass


class M3Checks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.program = json.loads((ROOT / 'build/polymorphic.json').read_text())
        cls.helper = P4InfoHelper(str(ROOT / 'build/polymorphic.p4.p4info.txtpb'))

    def packet(self, **kwargs):
        return ethernet(0x0800, ipv4(17, udp(), **kwargs))

    def run_packet(self, wire=None, **kwargs):
        return OfflineIngress(self.program, self.packet() if wire is None else wire, **kwargs).ingress()

    def assert_not_scheduled(self, packet, dropped=False):
        self.assertEqual(packet.fields['standard_metadata', 'mcast_grp'], 0)
        self.assertEqual(packet.registers, [0, 0])
        self.assertEqual(packet.dropped, dropped)

    def test_eligibility_mutations(self):
        # Mutate one precondition at a time; this exercises compiled predicates.
        for field, value in ((('standard_metadata', 'ingress_port'), 2),
                             (('ethernet', 'etherType'), 0x1234),
                             (('ipv4', 'version'), 6), (('ipv4', 'ihl'), 6),
                             (('ipv4', 'flags'), 1), (('ipv4', 'flags'), 4),
                             (('ipv4', 'fragOffset'), 1), (('ipv4', 'protocol'), 6),
                             (('ipv4', 'totalLen'), 43), (('ipv4', 'totalLen'), 45),
                             (('udp', 'dstPort'), 4321), (('udp', 'pkt_length'), 23),
                             (('standard_metadata', 'packet_length'), 57)):
            with self.subTest(field=field, value=value):
                p = OfflineIngress(self.program, self.packet())
                p.fields[field] = value
                self.assert_not_scheduled(p.ingress())
        for header in ('ethernet', 'ipv4', 'udp', 'protected_data'):
            with self.subTest(invalid_header=header):
                p = OfflineIngress(self.program, self.packet())
                p.valid.discard(header)
                self.assert_not_scheduled(p.ingress())

    def test_ordinary_wire_packets_and_table_miss(self):
        wires = [ethernet(0x0800, ipv4(17, udp(4321))),
                 ethernet(0x0800, ipv4(17, udp(data=b'short'))),
                 ethernet(0x0800, ipv4(17, udp(), ihl=6)),
                 ethernet(0x0800, ipv4(17, udp(), fragment=0x2000)),
                 ethernet(0x0800, ipv4(17, udp(), fragment=1)),
                 ethernet(0x0800, ipv4(1, bytes(32))),
                 ethernet(0x1234, sr(ipv4(17, udp(4321))))]
        for wire in wires:
            with self.subTest(wire=wire.hex()):
                self.assert_not_scheduled(self.run_packet(wire))
        miss = self.run_packet(rules={})
        self.assert_not_scheduled(miss)
        self.assertIn('MyIngress.ipv4_lpm', miss.visited)

    def test_parser_errors_drop_before_tables(self):
        wires = [self.packet()[:-1], ethernet(0x86dd, ipv6(253, b'PO')),
                 ethernet(0x0800, ipv4(253, shim(1, ipv4(17, udp()), magic=0)))]
        for wire in wires:
            p = self.run_packet(wire)
            self.assert_not_scheduled(p, dropped=True)
            self.assertNotIn('MyIngress.polymorphic_schedule', p.visited)
            self.assertNotIn('MyIngress.ipv4_lpm', p.visited)

    def test_encapsulated_packets_never_reschedule(self):
        for mode, wrap, kind in ((1, lambda p: ipv4(253, p), 0x0800),
                                 (2, lambda p: ipv6(253, p), 0x86dd), (3, sr, 0x1234)):
            for direction in (0, 1):
                wire = ethernet(kind, wrap(shim(mode, ipv4(17, udp()), direction)))
                p = self.run_packet(wire)
                # This interpreter installs only schedule entries. The original
                # IPv6 table defaults to drop until forwarding entries exist.
                self.assert_not_scheduled(p, dropped=(mode == 2))
                if mode == 2:
                    self.assertIn('MyIngress.ipv6_lpm', p.visited)
                self.assertEqual(p.fields['poly', 'sequence_number'], 0x12345678)
        for field, value in ((('poly', 'direction'), 2), (('poly', 'modality_id'), 0),
                             (('poly', 'modality_id'), 4), (('poly', 'modality_id'), 2),
                             (('inner_ipv4', 'totalLen'), 43), (('udp', 'dstPort'), 4321)):
            p = OfflineIngress(self.program, ethernet(0x0800, ipv4(253, shim(1, ipv4(17, udp())))))
            p.fields[field] = value
            self.assert_not_scheduled(p.ingress(), dropped=True)

    def test_sequence_headers_direction_and_wrap(self):
        registers = [0, 0]
        for expected in range(1, 6):
            p = self.run_packet(registers=registers)
            self.assertEqual(p.fields['poly', 'sequence_number'], expected)
            self.assertEqual(registers, [expected, 0])
            self.assertEqual(p.fields['poly', 'direction'], 0)
            self.assertEqual(p.fields['poly', 'modality_id'], 0)
            self.assertIn('inner_ipv4', p.valid)
            self.assertNotIn('ipv4', p.valid)
            self.assertEqual(p.fields['inner_ipv4', 'ttl'], 64)
            self.assertEqual(p.fields['standard_metadata', 'mcast_grp'], 10)
            self.assertNotIn('MyIngress.ipv4_lpm', p.visited)
        reverse = self.run_packet(registers=registers, rules={(1, 0x0a000202, 5000): 1})
        self.assertEqual(reverse.fields['poly', 'sequence_number'], 1)
        self.assertEqual(reverse.fields['poly', 'direction'], 1)
        self.assertEqual(registers, [5, 1])
        # A separate switch has independent local storage.
        self.assertEqual(self.run_packet().fields['poly', 'sequence_number'], 1)
        for expected in (0xffffffff, 0, 1):
            if expected == 0xffffffff:
                registers[0] = 0xfffffffe
            p = self.run_packet(registers=registers)
            self.assertEqual(p.fields['poly', 'sequence_number'], expected)
        self.assert_not_scheduled(self.run_packet(rules={(1, 0x0a000202, 5000): 2}), dropped=True)

    def test_crc_order_and_stable_fields(self):
        p = self.run_packet()
        expected = bytes.fromhex('0a0001010a00020211c0001388') + b'0123456789abcdef'
        self.assertEqual(len(expected), 29)
        self.assertEqual(p.hash_inputs, [expected])
        self.assertEqual(p.fields['poly', 'source_crc32'], zlib.crc32(expected))
        padded = self.run_packet(self.packet() + bytes(2))
        self.assertEqual(padded.hash_inputs, [expected])
        # Independent bitwise reflected CRC confirms Python's CRC convention.
        crc = 0xffffffff
        for byte in expected:
            crc ^= byte
            for _ in range(8):
                crc = (crc >> 1) ^ (0xedb88320 if crc & 1 else 0)
        self.assertEqual(crc ^ 0xffffffff, zlib.crc32(expected))
        for field in (('ipv4', 'ttl'), ('ipv4', 'hdrChecksum'), ('ethernet', 'srcAddr'),
                      ('ethernet', 'dstAddr')):
            q = OfflineIngress(self.program, self.packet())
            q.fields[field] ^= 1
            self.assertEqual(q.ingress().fields['poly', 'source_crc32'], zlib.crc32(expected))
        for field in (('ipv4', 'srcAddr'), ('ipv4', 'dstAddr'), ('udp', 'srcPort'),
                      ('protected_data', 'value')):
            q = OfflineIngress(self.program, self.packet())
            q.fields[field] ^= 1
            # Destination mutations also require a matching schedule entry.
            q.rules = {(1, q.fields['ipv4', 'dstAddr'], 5000): 0}
            self.assertNotEqual(q.ingress().fields['poly', 'source_crc32'], zlib.crc32(expected))
        prepare = next(a for a in self.program['actions'] if a['name'] == 'MyIngress.prepare_polymorphic')
        primitive = next(q for q in prepare['primitives'] if q['op'] == 'modify_field_with_hash_based_offset')
        self.assertEqual(int(primitive['parameters'][3]['value'], 16), 1 << 32)
        # Boundary value must not be reduced to zero by an incorrect max.
        with patch('zlib.crc32', return_value=0xffffffff):
            self.assertEqual(self.run_packet().fields['poly', 'source_crc32'], 0xffffffff)

    def test_pre_replica_snapshot_model(self):
        p = self.run_packet()
        replicas = [(port, instance, copy.deepcopy(p.fields))
                    for port, instance in controller.POLY_REPLICAS]
        self.assertEqual([(p, i) for p, i, _ in replicas], [(2, 1), (3, 2), (4, 3)])
        self.assertEqual({f['poly', 'sequence_number'] for _, _, f in replicas}, {1})
        self.assertEqual(len({f['poly', 'source_crc32'] for _, _, f in replicas}), 1)
        self.assertEqual(p.registers, [1, 0])

    def test_capture_checker_with_synthetic_fixture(self):
        # Synthetic files test the checker only; these are NOT switch captures.
        p = self.run_packet()
        wire = p.deparse()
        record = struct.pack('<IIII', 0, 0, len(wire), len(wire)) + wire
        header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        with tempfile.TemporaryDirectory() as folder:
            paths = [Path(folder) / f'port{port}.pcap' for port in (2, 3, 4)]
            for path in paths:
                path.write_bytes(header + record)
            self.assertEqual(check_pcaps(paths, 0, 1), [(1, p.fields['poly', 'source_crc32'])])
            paths[2].write_bytes(header)
            with self.assertRaises(ValueError):
                check_pcaps(paths, 0, 1)

    def test_p4info_and_real_p4runtime_requests(self):
        h = self.helper
        self.assertEqual([(r['size'], r['bitwidth']) for r in self.program['register_arrays']
                          if r['name'] == 'MyIngress.sequence_register'], [(2, 32)])
        table = h.get('tables', name='MyIngress.polymorphic_schedule')
        self.assertEqual([(f.name, f.bitwidth, f.match_type) for f in table.match_fields],
                         [('standard_metadata.ingress_port', 9, p4info_pb2.MatchField.EXACT),
                          ('hdr.ipv4.dstAddr', 32, p4info_pb2.MatchField.EXACT),
                          ('hdr.udp.dstPort', 16, p4info_pb2.MatchField.EXACT)])
        action = h.get('actions', name='MyIngress.start_polymorphic')
        self.assertEqual([(p.name, p.bitwidth) for p in action.params], [('packet_direction', 8)])
        switches = {}
        def connect(**kwargs):
            switch = RecordingSwitch(**kwargs)
            switches[switch.name] = switch
            return switch
        with patch.object(controller.p4runtime_lib.bmv2, 'Bmv2SwitchConnection', side_effect=connect), \
                patch.object(controller, 'ShutdownAllSwitchConnections'):
            controller.main(str(ROOT / 'build/polymorphic.p4.p4info.txtpb'),
                            str(ROOT / 'build/polymorphic.json'))
        self.assertEqual(len(switches), 10)
        ordinary = {h.get_tables_id('MyIngress.ipv4_lpm'): 0,
                    h.get_tables_id('MyIngress.ipv6_lpm'): 0,
                    h.get_tables_id('MyIngress.arp_match'): 0}
        destination_counts = {'s1': 0, 's2': 0}
        destination_defaults = {'s1': 0, 's2': 0}
        for name, switch in switches.items():
            pre, schedules = [], []
            for request in switch.requests:
                self.assertEqual(request.device_id, switch.device_id)
                self.assertEqual(request.election_id.low, 1)
                is_default = request.updates[0].entity.table_entry.is_default_action
                self.assertEqual(request.updates[0].type, p4runtime_pb2.Update.MODIFY
                                 if is_default else p4runtime_pb2.Update.INSERT)
                # Exercise serialization of actual protobufs, not dict stubs.
                restored = p4runtime_pb2.WriteRequest.FromString(request.SerializeToString())
                entity = restored.updates[0].entity
                if entity.HasField('packet_replication_engine_entry'):
                    pre.append(entity.packet_replication_engine_entry.multicast_group_entry)
                else:
                    entry = entity.table_entry
                    if entry.table_id == table.preamble.id:
                        schedules.append(entry)
                    elif entry.table_id == h.get_tables_id('MyIngress.polymorphic_destination'):
                        self.assertIn(name, destination_counts)
                        if entry.is_default_action:
                            destination_defaults[name] += 1
                        else:
                            destination_counts[name] += 1
                    else:
                        ordinary[entry.table_id] += 1
            if name in ('s1', 's2'):
                self.assertEqual(len(pre), 1)
                self.assertEqual(pre[0].multicast_group_id, 10)
                self.assertEqual([(r.egress_port, r.instance) for r in pre[0].replicas],
                                 [(2, 1), (3, 2), (4, 3)])
                self.assertEqual(len(schedules), 1)
                entry = schedules[0]
                self.assertEqual(entry.action.action.action_id, action.preamble.id)
                self.assertEqual(entry.action.action.params[0].value, bytes([int(name == 's2')]))
                actual = {h.get_match_field_name(table.preamble.name, f.field_id): f.exact.value
                          for f in entry.match}
                self.assertEqual(actual, {'standard_metadata.ingress_port': b'\x00\x01',
                    'hdr.ipv4.dstAddr': ipaddress.ip_address('10.0.2.2' if name == 's1' else '10.0.1.1').packed,
                    'hdr.udp.dstPort': (5000).to_bytes(2, 'big')})
            else:
                self.assertEqual((pre, schedules), ([], []))
        self.assertEqual(sorted(ordinary.values()), [2, 8, 8])
        self.assertEqual(destination_counts, {'s1': 3, 's2': 3})
        self.assertEqual(destination_defaults, {'s1': 1, 's2': 1})
        with self.assertRaises(ValueError):
            controller.writePolymorphicScheduleRule(h, switches['s1'], '10.0.2.2', 2)


if __name__ == '__main__':
    print('OFFLINE ONLY: JSON interpretation, Python CRC/PRE models, protobuf construction.', flush=True)
    unittest.main(verbosity=2)
