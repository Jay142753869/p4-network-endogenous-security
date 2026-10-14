#!/usr/bin/env python3
"""P4Runtime multicast helper used by the lesson-2 controller TODO.

Copy the function into mycontroller.py.  The caller is responsible for
passing the already connected S1 or S2 switch object.
"""

POLY_MCAST_GROUP = 10


def writeMulticastGroup(p4info_helper, switch):
    """Install group 10: ports 2/3/4 with distinct replica instances."""
    replicas = [
        {"egress_port": 2, "instance": 1},
        {"egress_port": 3, "instance": 2},
        {"egress_port": 4, "instance": 3},
    ]
    entry = p4info_helper.buildMulticastGroupEntry(
        POLY_MCAST_GROUP,
        replicas,
    )
    switch.WritePREEntry(entry)


def writePolymorphicScheduleRule(
    p4info_helper,
    switch,
    destination,
    direction,
):
    """Match a host-facing UDP/5000 packet and mark it for scheduling."""
    entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.polymorphic_schedule",
        match_fields={
            "standard_metadata.ingress_port": 1,
            "hdr.ipv4.dstAddr": destination,
            "hdr.udp.dstPort": 5000,
        },
        action_name="MyIngress.start_polymorphic",
        action_params={"packet_direction": direction},
    )
    switch.WriteTableEntry(entry)


# 双向调用示例（放在连接和 pipeline 配置完成之后）：
# writePolymorphicScheduleRule(p4info_helper, s1, "10.0.2.2", 0)
# writePolymorphicScheduleRule(p4info_helper, s2, "10.0.1.1", 1)
# writeMulticastGroup(p4info_helper, s1)
# writeMulticastGroup(p4info_helper, s2)

