#!/usr/bin/env python3
"""Ordinary forwarding, M3 scheduling and M5 destination adjudication rules.

M6 restoration is still unimplemented; winners remain safely dropped.
"""

import argparse
import grpc
import os
import sys
from time import sleep

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 'utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

POLY_MCAST_GROUP = 10
POLY_REPLICAS = ((2, 1), (3, 2), (4, 3))


def writeMulticastGroup(p4info_helper, switch, group_id=POLY_MCAST_GROUP,
                        replicas=POLY_REPLICAS):
    """Write PRE replicas as (egress_port, instance), not the reverse."""
    entry = p4info_helper.buildMulticastGroupEntry(
        group_id,
        [{"egress_port": port, "instance": instance}
         for port, instance in replicas],
    )
    switch.WritePREEntry(entry)


def writePolymorphicScheduleRule(p4info_helper, switch, destination,
                                  packet_direction):
    """Schedule only host-port input; the P4 ingress checks the full format."""
    if packet_direction not in (0, 1):
        raise ValueError("packet_direction must be 0 or 1")
    entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.polymorphic_schedule",
        match_fields={
            "standard_metadata.ingress_port": 1,
            "hdr.ipv4.dstAddr": destination,
            "hdr.udp.dstPort": 5000,
        },
        action_name="MyIngress.start_polymorphic",
        action_params={"packet_direction": packet_direction},
    )
    switch.WriteTableEntry(entry)


def writePolymorphicDestinationRule(p4info_helper, switch, packet_direction,
                                     ingress_port, modality_id):
    """Select M5 adjudication for one valid arriving modality at its gateway."""
    if packet_direction not in (0, 1) or (ingress_port, modality_id) not in POLY_REPLICAS:
        raise ValueError("invalid destination direction or port/modality pair")
    entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.polymorphic_destination",
        match_fields={
            "standard_metadata.ingress_port": ingress_port,
            "hdr.poly.direction": packet_direction,
            "hdr.poly.modality_id": modality_id,
        },
        action_name="MyIngress.adjudicate_polymorphic",
    )
    switch.WriteTableEntry(entry)

def writeArp_matchRules(p4info_helper, sw, match_fields_1, match_fields_2, action_params):

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.arp_match",
        match_fields={
            "hdr.arp.oper": match_fields_1,
            "hdr.arp.tpa" : match_fields_2
        },
        action_name="MyIngress.send_arp_reply",
        action_params=action_params
        )
    sw.WriteTableEntry(table_entry)
    
def writeIpv4_lpmRules(p4info_helper, sw, match_fields, action_params):

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": match_fields
        },
        action_name="MyIngress.ipv4_forward",
        action_params=action_params
        )
    sw.WriteTableEntry(table_entry)
    
def writeIpv6_lpmRules(p4info_helper, sw, match_fields, action_params):

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv6_lpm",
        match_fields={
            "hdr.ipv6.dstAddr": match_fields
        },
        action_name="MyIngress.ipv6_forward",
        action_params=action_params
        )
    sw.WriteTableEntry(table_entry)


def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for switches;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')
        s11 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s11',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='logs/s11-p4runtime-requests.txt')
        s12 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s12',
            address='127.0.0.1:50054',
            device_id=3,
            proto_dump_file='logs/s12-p4runtime-requests.txt')
        s21 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s21',
            address='127.0.0.1:50055',
            device_id=4,
            proto_dump_file='logs/s21-p4runtime-requests.txt')
        s22 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s22',
            address='127.0.0.1:50056',
            device_id=5,
            proto_dump_file='logs/s22-p4runtime-requests.txt')
        s31 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s31',
            address='127.0.0.1:50057',
            device_id=6,
            proto_dump_file='logs/s31-p4runtime-requests.txt')
        s32 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s32',
            address='127.0.0.1:50058',
            device_id=7,
            proto_dump_file='logs/s32-p4runtime-requests.txt')
        s41 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s41',
            address='127.0.0.1:50059',
            device_id=8,
            proto_dump_file='logs/s41-p4runtime-requests.txt')
        s42 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s42',
            address='127.0.0.1:50060',
            device_id=9,
            proto_dump_file='logs/s42-p4runtime-requests.txt')


        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s11.MasterArbitrationUpdate()
        s12.MasterArbitrationUpdate()
        s21.MasterArbitrationUpdate()
        s22.MasterArbitrationUpdate()
        s31.MasterArbitrationUpdate()
        s32.MasterArbitrationUpdate()
        s41.MasterArbitrationUpdate()
        s42.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        s11.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        s12.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        s21.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        s22.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        s31.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        s32.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        s41.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        s42.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        
        writeArp_matchRules(p4info_helper, s1, [1], ["10.0.1.10", 32], {"macAddr": "08:00:00:00:01:00"})
        writeArp_matchRules(p4info_helper, s2, [1], ["10.0.2.20", 32], {"macAddr": "08:00:00:00:02:00"})
        

        # Table entries for ipv4
        # h1 -> h2
        writeIpv4_lpmRules(p4info_helper, s1, ["10.0.2.2", 32], {"dstAddr": "08:00:00:00:11:00", "port": 2})
        writeIpv4_lpmRules(p4info_helper, s11, ["10.0.2.2", 32], {"dstAddr": "08:00:00:00:12:00", "port": 2})
        writeIpv4_lpmRules(p4info_helper, s12, ["10.0.2.2", 32], {"dstAddr": "08:00:00:00:02:00", "port": 2})
        writeIpv4_lpmRules(p4info_helper, s2, ["10.0.2.2", 32], {"dstAddr": "08:00:00:00:02:02", "port": 1})
        
        # h2 -> h1
        writeIpv4_lpmRules(p4info_helper, s2, ["10.0.1.1", 32], {"dstAddr": "08:00:00:00:12:00", "port": 2})
        writeIpv4_lpmRules(p4info_helper, s12, ["10.0.1.1", 32], {"dstAddr": "08:00:00:00:11:00", "port": 1})
        writeIpv4_lpmRules(p4info_helper, s11, ["10.0.1.1", 32], {"dstAddr": "08:00:00:00:01:00", "port": 1})
        writeIpv4_lpmRules(p4info_helper, s1, ["10.0.1.1", 32], {"dstAddr": "08:00:00:00:01:01", "port": 1})
        
        # Table entries for ipv6
        # h1 -> h2
        writeIpv6_lpmRules(p4info_helper, s1, ["fe80::5678", 128], {"dstAddr": "08:00:00:00:11:00", "port": 3})
        writeIpv6_lpmRules(p4info_helper, s21, ["fe80::5678", 128], {"dstAddr": "08:00:00:00:12:00", "port": 2})
        writeIpv6_lpmRules(p4info_helper, s22, ["fe80::5678", 128], {"dstAddr": "08:00:00:00:02:00", "port": 2})
        writeIpv6_lpmRules(p4info_helper, s2, ["fe80::5678", 128], {"dstAddr": "08:00:00:00:02:02", "port": 1})
        
        # h2 -> h1
        writeIpv6_lpmRules(p4info_helper, s2, ["fe80::1234", 128], {"dstAddr": "08:00:00:00:12:00", "port": 3})
        writeIpv6_lpmRules(p4info_helper, s22, ["fe80::1234", 128], {"dstAddr": "08:00:00:00:11:00", "port": 1})
        writeIpv6_lpmRules(p4info_helper, s21, ["fe80::1234", 128], {"dstAddr": "08:00:00:00:01:00", "port": 1})
        writeIpv6_lpmRules(p4info_helper, s1, ["fe80::1234", 128], {"dstAddr": "08:00:00:00:01:01", "port": 1})

        # Enable adjudication for all three destination arrivals before input.
        # Intermediate switches receive no destination-gateway rules.
        for gateway in (s1, s2):
            # Fail closed at gateways if an exact arrival rule is absent.
            entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.polymorphic_destination",
                default_action=True,
                action_name="MyIngress.hold_polymorphic",
            )
            gateway.WriteTableEntry(entry)
        for ingress_port, modality_id in ((2, 1), (3, 2), (4, 3)):
            writePolymorphicDestinationRule(p4info_helper, s2, 0, ingress_port, modality_id)
            writePolymorphicDestinationRule(p4info_helper, s1, 1, ingress_port, modality_id)

        # Install PRE before enabling either source schedule. Intermediate
        # switches retain only their original ordinary forwarding entries.
        writeMulticastGroup(p4info_helper, s1)
        writeMulticastGroup(p4info_helper, s2)
        writePolymorphicScheduleRule(p4info_helper, s1, "10.0.2.2", 0)
        writePolymorphicScheduleRule(p4info_helper, s2, "10.0.1.1", 1)

        # TODO M6: restore only the current copy that first forms a majority.
        # Fault injection is deliberately left to a later stage.
        

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/polymorphic.p4.p4info.txtpb')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/polymorphic.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
