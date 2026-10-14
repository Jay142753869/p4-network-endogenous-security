#!/usr/bin/env python3
"""OFFLINE ONLY: actual compiled JSON actions + protobufs, modeled externs.

Temporary synthetic pcaps test the final checker. These are not native BMv2
five-scenario acceptance results and never print the official pass markers.
"""
import argparse
from collections import defaultdict
import copy
import itertools
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import check_m4 as m4
import check_m5 as m5
import check_m6 as m6
import check_final_pcaps as final

ROOT, controller = m4.ROOT, m4.controller


def configured(helper, faults=()):
    switches = {}
    def connect(**kwargs):
        switch = m4.RecordingSwitch(**kwargs)
        switches[switch.name] = switch
        return switch
    with patch.object(controller.p4runtime_lib.bmv2, 'Bmv2SwitchConnection', side_effect=connect), \
            patch.object(controller, 'ShutdownAllSwitchConnections'):
        result = controller.main(str(ROOT / 'build/polymorphic.p4.p4info.txtpb'),
                                 str(ROOT / 'build/polymorphic.json'), faults)
        if result != 0:
            raise AssertionError('offline controller setup failed')
    entries = {name: [r.updates[0].entity.table_entry for r in switch.requests
                     if r.updates[0].entity.HasField('table_entry')]
               for name, switch in switches.items()}
    return entries, switches


class FaultChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.program = json.loads((ROOT / 'build/polymorphic.json').read_text())
        cls.helper = m4.P4InfoHelper(str(ROOT / 'build/polymorphic.p4.p4info.txtpb'))
        cls.entries, _ = configured(cls.helper)

    def simulate(self, scenario, direction=None, order=(1, 2, 3), messages=None, faults=None):
        config = final.SCENARIOS[scenario]
        direction = int(config['sender'] == 'h2') if direction is None else direction
        faults = config['faults'] if faults is None else faults
        entries, switches = configured(self.helper, faults)
        source_name, dest_name = ('s1', 's2') if direction == 0 else ('s2', 's1')
        captures, nodes = defaultdict(list), {}
        for mode in (1, 2, 3):
            for point in m4.path_points(direction, mode):
                captures[point] = []
        captures[f'{dest_name}-eth1_out.pcap'] = []
        session = m5.Session(self, direction, entries=entries[dest_name])
        state = None
        for sequence, message in enumerate(messages or (config['message'].encode(),), 1):
            inner = m5.inner_packet(direction, message)
            original = m4.ethernet(0x0800, inner)
            captures[f'{source_name}-eth1_in.pcap'].append(original)
            source = m4.OfflineSwitch(self.program, original, self.helper, entries[source_name], state=state)
            source.pipeline('ingress')
            self.assertNotIn('MyIngress.polymorphic_fault', source.visited)
            state = source.state
            for mode in order:
                p = copy.deepcopy(source).egress(mode + 1, replication=True)
                wire = p.deparse()
                points = m4.path_points(direction, mode)
                captures[points[0]].append(wire)
                dropped = False
                for stage in (1, 3):
                    captures[points[stage]].append(wire)
                    name = points[stage].split('-')[0]
                    p = m4.OfflineSwitch(self.program, wire, self.helper, entries[name],
                                         port=1 if direction == 0 else 2)
                    p.pipeline('ingress')
                    nodes[sequence, mode, name] = p
                    self.assertEqual(p.visited.count('MyIngress.polymorphic_fault'), 1)
                    if p.dropped:
                        dropped = True
                        break
                    wire = p.egress().deparse()
                    captures[points[stage + 1]].append(wire)
                if dropped:
                    continue
                captures[points[5]].append(wire)
                p = session.send(sequence=sequence, mode=mode, wire=wire)
                if p.dropped:
                    m6.M6Checks.held(self, p)
                else:
                    captures[f'{dest_name}-eth1_out.pcap'].append(
                        m6.M6Checks.result(self, p, inner, direction))
        return captures, session, nodes, switches

    def test_parse_unsigned_fields_and_boundaries(self):
        for text, expected in [
                ('corrupt:1:1:0x1', ('corrupt', 1, 1, 1)),
                ('drop:3:0xffffffff', ('drop', 3, 0xffffffff, 0)),
                ('corrupt:2:0:0', ('corrupt', 2, 0, 0)),
                ('corrupt:03:0001:0XFF', ('corrupt', 3, 1, 255)),
                ('corrupt:1:4294967295:' + str((1 << 128) - 1),
                 ('corrupt', 1, 0xffffffff, (1 << 128) - 1))]:
            fault = controller.parse_fault(text)
            self.assertEqual((fault.operation, fault.mode, fault.sequence, fault.mask), expected)

    def test_invalid_arguments_and_conflicts_fail_before_network(self):
        bad = ['drop:0:1', 'drop:4:1', 'drop:1:-1', 'drop:1:4294967296',
               'corrupt:1:1:-1', 'corrupt:1:1:' + str(1 << 128), 'corrupt:1:1',
               'drop:1:1:1', 'wrong:1:1', 'drop:1:abc', 'drop:1: 1', 'drop:+1:1',
               'corrupt:1:1:0x', '']
        for value in bad:
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                controller.parse_fault(value)
        with patch.object(controller.p4runtime_lib.bmv2, 'Bmv2SwitchConnection') as connection:
            for faults in (['drop:0:1'], ['drop:1:1', 'corrupt:1:1:1']):
                with self.assertRaises((ValueError, argparse.ArgumentTypeError)):
                    controller.main('unused', 'unused', faults)
            connection.assert_not_called()
        for args in (['--fault', 'drop:0:1'],
                     ['--fault', 'drop:1:1', '--fault', 'corrupt:1:1:1']):
            run = subprocess.run(['python3', 'mycontroller.py'] + args, cwd=ROOT,
                                 capture_output=True, text=True)
            self.assertEqual(run.returncode, 2)
            self.assertIn('error:', run.stderr)

    def test_repeated_faults_are_idempotent_and_conflicts_rejected(self):
        self.assertEqual(len(controller.normalize_faults(['corrupt:1:1:1'] * 3)), 1)
        for values in (['corrupt:1:1:1', 'corrupt:1:1:2'], ['drop:1:1', 'corrupt:1:1:1']):
            with self.assertRaisesRegex(ValueError, 'conflicting'):
                controller.normalize_faults(values)
        self.assertEqual(len(controller.normalize_faults(['drop:1:1', 'drop:1:1025', 'drop:2:1'])), 3)
        captures, session, _, _ = self.simulate('corrupt-mode1', faults=['corrupt:1:1:1'] * 3)
        self.assertEqual(session.stats(), ([0, 1, 1], [1, 0, 0], 0))
        before = final.decode_copy(captures['s11-eth1_in.pcap'][0])
        after = final.decode_copy(captures['s11-eth2_out.pcap'][0])
        self.assertEqual(int.from_bytes(before.inner[28:], 'big') ^ int.from_bytes(after.inner[28:], 'big'), 1)

    def test_real_p4runtime_rule_construction_and_original_entries_preserved(self):
        faults = ['corrupt:1:4294967295:0x80000000000000000000000000000001',
                  'drop:2:0', 'corrupt:3:1025:2']
        entries, changed = configured(self.helper, faults)
        _, baseline = configured(self.helper)
        table = self.helper.get_tables_id('MyIngress.polymorphic_fault')
        for name in entries:
            rules = [e for e in entries[name] if e.table_id == table]
            self.assertEqual(len(rules), 2 if name in ('s11', 's21', 's31') else 0)
            old = [r.SerializeToString() for r in baseline[name].requests]
            new = [r.SerializeToString() for r in changed[name].requests
                   if not r.updates[0].entity.HasField('table_entry')
                   or r.updates[0].entity.table_entry.table_id != table]
            self.assertEqual(old, new, name)
            for rule in rules:
                key = tuple(int.from_bytes(f.exact.value, 'big') for f in rule.match)
                mode = {'s11': 1, 's21': 2, 's31': 3}[name]
                seq = {1: 0xffffffff, 2: 0, 3: 1025}[mode]
                self.assertIn(key, ((1, 0, mode, seq), (2, 1, mode, seq)))
                action = self.helper.get_actions_name(rule.action.action.action_id)
                self.assertEqual(action, 'MyIngress.fault_drop' if mode == 2 else 'MyIngress.fault_corrupt')
                if mode == 1:
                    self.assertEqual(int.from_bytes(rule.action.action.params[0].value, 'big'),
                                     (1 << 127) | 1)

    def test_mode_full_sequence_direction_and_port_exact_matching(self):
        for mode, switch in ((1, 's11'), (2, 's21'), (3, 's31')):
            entries, _ = configured(self.helper, [f'corrupt:{mode}:1:1'])
            for seq, packet_mode, direction, port, hit in (
                    (1, mode, 0, 1, True), (1, mode, 1, 2, True),
                    (1025, mode, 0, 1, False), (0xffffffff, mode, 0, 1, False),
                    (1, mode, 1, 1, False), (1, mode, 0, 2, False),
                    (1, mode % 3 + 1, 0, 1, False)):
                packet = m4.OfflineSwitch(self.program, m5.copy_packet(seq, packet_mode, direction=direction),
                                          self.helper, entries[switch], port=port)
                before = packet.fields['protected_data', 'value']
                packet.pipeline('ingress')
                self.assertEqual(packet.fields['protected_data', 'value'], before ^ int(hit))
            fault = controller.parse_fault(f'corrupt:{mode}:1:1')
            with self.assertRaises(ValueError):
                controller.writeFaultRule(self.helper, m4.RecordingSwitch('s1', '', 0), fault, 0)
            with self.assertRaises(ValueError):
                controller.writeFaultRule(self.helper, m4.RecordingSwitch(switch, '', 0), fault, 2)
        for sequence in (0, 0xffffffff):
            entries, _ = configured(self.helper, [f'corrupt:1:{sequence}:1'])
            packet = m4.OfflineSwitch(self.program, m5.copy_packet(sequence, 1),
                                      self.helper, entries['s11'], port=1)
            before = packet.fields['protected_data', 'value']
            packet.pipeline('ingress')
            self.assertEqual(packet.fields['protected_data', 'value'], before ^ 1)

    def test_full_128bit_xor_changes_only_actual_protected_data(self):
        for mask in (0, 1, 1 << 127, (1 << 128) - 1):
            entries, _ = configured(self.helper, [f'corrupt:1:1:{mask}'])
            packet = m4.OfflineSwitch(self.program, m5.copy_packet(1, 1, data=bytes(range(16))),
                                      self.helper, entries['s11'], port=1)
            before = {key: value for key, value in packet.fields.items()
                      if key[0] in ('poly', 'inner_ipv4', 'udp', 'protected_data')}
            packet.pipeline('ingress')
            for key, value in before.items():
                self.assertEqual(packet.fields[key], value ^ mask if key == ('protected_data', 'value') else value)

    def test_drop_exits_before_forwarding_and_does_not_count(self):
        entries, _ = configured(self.helper, ['drop:2:1'])
        packet = m4.OfflineSwitch(self.program, m5.copy_packet(1, 2), self.helper, entries['s21'], port=1)
        packet.pipeline('ingress')
        self.assertTrue(packet.dropped)
        self.assertNotIn('MyIngress.ipv6_lpm', packet.visited)
        self.assertNotIn('MyIngress.polymorphic_destination', packet.visited)
        self.assertFalse(any(any(values) for values in packet.state['counters'].values()))

    def test_all_five_official_scenarios_both_directions_all_orders_OFFLINE(self):
        for scenario in final.SCENARIOS:
            for direction in (0, 1):
                for order in itertools.permutations((1, 2, 3)):
                    with self.subTest(scenario=scenario, direction=direction, order=order):
                        captures, session, _, _ = self.simulate(scenario, direction, order)
                        self.assertEqual(session.stats(), final.expected_stats(scenario))
                        self.assertEqual(sum(session.accepts), final.SCENARIOS[scenario]['expected'])
                        dest = 's2' if direction == 0 else 's1'
                        self.assertEqual(len(captures[f'{dest}-eth1_out.pcap']), final.SCENARIOS[scenario]['expected'])

    def test_only_target_sequence_faulted_across_continuous_sends(self):
        captures, session, _, _ = self.simulate('corrupt-mode1', messages=(b'first', b'second'))
        self.assertEqual(session.stats(), ([1, 2, 2], [1, 0, 0], 0))
        self.assertEqual(sum(session.accepts), 2)
        for index, wire in enumerate(captures['s11-eth2_out.pcap'], 1):
            p = final.decode_copy(wire)
            self.assertEqual(p.sequence, index)
            self.assertEqual(p.source_crc == p.observed_crc, index == 2)

    def test_ordinary_protocols_and_invalid_poly_never_reach_fault_table(self):
        entries, _ = configured(self.helper, ['corrupt:1:1:1', 'drop:2:1', 'corrupt:3:1:1'])
        for switch, wire in (
                ('s11', m4.ethernet(0x0800, m4.ipv4(17, m4.udp(4321)))),
                ('s21', m4.ethernet(0x86dd, m4.ipv6(17, m4.udp(4321)))),
                ('s31', m4.ethernet(0x1234, m4.sr(m4.ipv4(17, m4.udp(4321))))),
                ('s1', m4.ethernet(0x0806, bytes(28)))):
            p = m4.OfflineSwitch(self.program, wire, self.helper, entries[switch])
            p.pipeline('ingress')
            self.assertNotIn('MyIngress.polymorphic_fault', p.visited)
        p = m4.OfflineSwitch(self.program, m5.copy_packet(1, 1), self.helper, entries['s11'])
        p.fields['poly', 'direction'] = 2
        p.pipeline('ingress')
        self.assertTrue(p.dropped)
        self.assertNotIn('MyIngress.polymorphic_fault', p.visited)

    def counters_text(self, session, direction):
        good, bad, no_majority = session.stats()
        result = []
        for name in ('s1', 's2'):
            g, b, n = (good, bad, no_majority) if name == ('s2' if direction == 0 else 's1') \
                else ([0, 0, 0], [0, 0, 0], 0)
            result.append(name + ' ' + ' '.join(f'mode{m}_good={g[m-1]} mode{m}_bad={b[m-1]}'
                                               for m in (1, 2, 3)) + f' no_majority={n}\n')
        return ''.join(result)

    def check_fixture(self, captures, scenario, session, direction=0):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            for filename, wires in captures.items():
                m6.write_synthetic_pcap(folder / filename, wires)
            counts = folder / 'counters.log'
            counts.write_text(self.counters_text(session, direction))
            return final.check(folder, scenario, counts, direction)

    def test_final_pcap_checker_all_scenarios_both_directions_SYNTHETIC(self):
        for scenario in final.SCENARIOS:
            for direction in (0, 1):
                captures, session, _, _ = self.simulate(scenario, direction, order=(3, 2, 1))
                source_crc, observed, outputs = self.check_fixture(captures, scenario, session, direction)
                self.assertEqual(outputs, final.SCENARIOS[scenario]['expected'])
                if scenario == 'no-majority':
                    self.assertEqual(len(set(observed.values())), 3)
                    self.assertNotIn(source_crc, observed.values())
                if scenario == 'drop-mode2':
                    self.assertIsNone(observed[2])

    def test_final_pcap_checker_rejects_no_fault_double_xor_crc_coverup_and_duplicates(self):
        captures, session, _, _ = self.simulate('corrupt-mode1')
        mutations = []
        for operation in ('cancel-xor', 'source-crc-coverup'):
            c = copy.deepcopy(captures)
            wire = bytearray(c['s11-eth2_out.pcap'][0])
            if operation == 'cancel-xor':
                wire[-1] ^= 1
            else:
                wire[42] ^= 1  # advertised source CRC inside PolyShim
            c['s11-eth2_out.pcap'] = [bytes(wire)]
            mutations.append(c)
        c = copy.deepcopy(captures)
        c['s2-eth1_out.pcap'] *= 2
        mutations.append(c)
        no_fault, _, _, _ = self.simulate('no-fault')
        mutations.append(no_fault)
        for c in mutations:
            with self.assertRaises((ValueError, OSError)):
                self.check_fixture(c, 'corrupt-mode1', session)
        dropped, session, _, _ = self.simulate('drop-mode2')
        dropped['s21-eth2_out.pcap'] = no_fault['s21-eth2_out.pcap']
        with self.assertRaises(ValueError):
            self.check_fixture(dropped, 'drop-mode2', session)

    def test_p4info_and_fault_action_write_scope(self):
        table = self.helper.get('tables', name='MyIngress.polymorphic_fault')
        self.assertEqual([(f.name, f.bitwidth) for f in table.match_fields],
                         [('standard_metadata.ingress_port', 9), ('hdr.poly.direction', 8),
                          ('hdr.poly.modality_id', 8), ('hdr.poly.sequence_number', 32)])
        action = self.helper.get('actions', name='MyIngress.fault_corrupt')
        self.assertEqual([(p.name, p.bitwidth) for p in action.params], [('xor_mask', 128)])
        compiled = next(a for a in self.program['actions'] if a['name'] == 'MyIngress.fault_corrupt')
        self.assertEqual(len(compiled['primitives']), 1)
        self.assertEqual(compiled['primitives'][0]['op'], 'assign')
        self.assertEqual(compiled['primitives'][0]['parameters'][0]['value'], ['protected_data', 'value'])
        # Keep the official driver, scenarios, receiver and counter expectations intact.
        subprocess.check_call(['git', '--git-dir=.course-git', '--work-tree=.', 'diff', '--exit-code',
                               '888db03', '--', 'run-poly-tests.py', 'send-poly.py', 'receive-poly.py',
                               'read-counters.py', 'evaluate-counters.py'], cwd=ROOT)

    def test_controller_reports_rpc_failure_and_closes_connections(self):
        with patch.object(controller.p4runtime_lib.bmv2, 'Bmv2SwitchConnection',
                          side_effect=controller.grpc.RpcError('offline stub failure')), \
                patch.object(controller, 'printGrpcError') as printer, \
                patch.object(controller, 'ShutdownAllSwitchConnections') as shutdown:
            self.assertEqual(controller.main(str(ROOT / 'build/polymorphic.p4.p4info.txtpb'), 'unused'), 1)
            printer.assert_called_once()
            shutdown.assert_called_once()


if __name__ == '__main__':
    print('OFFLINE ONLY: compiled P4 JSON and real protobuf construction; Python extern models and '
          'temporary SYNTHETIC pcaps. NOT native BMv2 five-scenario acceptance.', flush=True)
    unittest.main(verbosity=2)
