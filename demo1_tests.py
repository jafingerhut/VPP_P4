#!/usr/bin/env python2

'''Test cases for P4 program demo1.p4_16.p4'''

from __future__ import print_function
from scapy.all import *
# The following line isn't really necessary given the previous import
# line, but it does help avoid many 'undefined variable' pylint
# warnings
from scapy.all import TCP, Ether, IP
import runtime_CLI
import sstf_lib as sstf


# p4c as of about 2018-Jan uses hierarchical names for table and
# extern instance names.
ipfx = "ingress."
epfx = "egress."

# No prefix necessary for P4_14 programs, since all tables are
# global in scope.
#ipfx = ""
#epfx = ""


def update_macs_dec_ipv4_ttl(orig_eth_ipv4_pkt, new_src_mac='unchanged',
                             new_dst_mac='unchanged'):
    """This function is useful for creating an expected output packet from
    an input packet that begins with an Ethernet header, followed
    by an IPv4 header, when the only changes expected to be made to
    the packet are: change the Ethernet source and destination MAC
    addresses, and decrement the IPv4 TTL."""

    new_pkt = orig_eth_ipv4_pkt.copy()
    if new_src_mac != 'unchanged':
        new_pkt[Ether].src = new_src_mac
    if new_dst_mac != 'unchanged':
        new_pkt[Ether].dst = new_dst_mac
    new_pkt[IP].ttl -= 1
    return new_pkt


def table_entries_unicast(hdl, exp_src_mac, exp_dst_mac, port_mtu):
    """Add some table entries useful for testing some IPv4 unicast
    forwarding code."""

    hdl.do_table_add("%sipv4_da_lpm %sset_l2ptr 10.1.0.1/32 => 58" % (ipfx, ipfx))
    hdl.do_table_add("%sipv4_da_lpm %sset_l2ptr 10.1.0.34/32 => 58" % (ipfx, ipfx))
    hdl.do_table_add("%sipv4_da_lpm %sset_l2ptr 10.1.0.32/32 => 45" % (ipfx, ipfx))
    hdl.do_table_add("%smac_da %sset_bd_dmac_intf 58 => 9 %s 2" % (ipfx, ipfx, exp_dst_mac))
    hdl.do_table_add("%smac_da %sset_bd_dmac_intf 45 => 7 %s 3" % (ipfx, ipfx, exp_dst_mac))
    hdl.do_table_add("%ssend_frame %srewrite_mac 9 => %s" % (epfx, epfx, exp_src_mac))
    hdl.do_table_add("%ssend_frame %srewrite_mac 7 => %s" % (epfx, epfx, exp_src_mac))
    hdl.do_table_add("%smtu_check %sassign_mtu 9 => %s" % (epfx, epfx, str(port_mtu[2])))
    hdl.do_table_add("%smtu_check %sassign_mtu 7 => %s" % (epfx, epfx, str(port_mtu[3])))


def test_mtu_regular(hdl, port_int_map, exp_src_mac, exp_dst_mac):
    """IPv4 unicast forwarding cases where packets are forwarded normally,
    without dropping."""

    tcp_payload = "a" * 80
    fwd_pkt1 = Ether() / IP(dst='10.1.0.1') / TCP(sport=5793, dport=80)
    fwd_pkt2 = Ether() / IP(dst='10.1.0.34') / TCP(sport=5793, dport=80)
    fwd_pkt3 = (Ether() / IP(dst='10.1.0.32') / TCP(sport=5793, dport=80) /
                Raw(tcp_payload))

    exp_pkt1 = update_macs_dec_ipv4_ttl(fwd_pkt1, exp_src_mac, exp_dst_mac)
    exp_pkt2 = update_macs_dec_ipv4_ttl(fwd_pkt2, exp_src_mac, exp_dst_mac)
    exp_pkt3 = update_macs_dec_ipv4_ttl(fwd_pkt3, exp_src_mac, exp_dst_mac)

    # The following two commented-out lines can be used for verifying
    # that comparison of expected and captured packet can detect
    # mismatches in packet lengths.
    #exp_pkt1 = Ether(str(exp_pkt1)[:-1])
    #fwd_pkt1 = Ether(str(fwd_pkt1)[:-1])

    cap_pkts = sstf.send_pkts_and_capture(port_int_map,
                                          [{'port': 0, 'packet': fwd_pkt1},
                                           {'port': 1, 'packet': fwd_pkt2},
                                           {'port': 1, 'packet': fwd_pkt3}])
    input_ports = {0, 1}
    output = sstf.check_out_pkts([{'port': 2, 'packet': exp_pkt1},
                                  {'port': 2, 'packet': exp_pkt2},
                                  {'port': 3, 'packet': exp_pkt3}],
                                 cap_pkts, input_ports)

    # The calls to check_out_pkts() below can be used for verifying
    # that comparison of expected and captured packets can detect
    # mismatches in the number of packets.
#    output = sstf.check_out_pkts([{'port': 2, 'packet': exp_pkt1},
#                                  {'port': 2, 'packet': exp_pkt2},
#                                  {'port': 3, 'packet': exp_pkt3},
#                                  {'port': 3, 'packet': exp_pkt3}],
#                                 cap_pkts, input_ports)
#    output = sstf.check_out_pkts([{'port': 2, 'packet': exp_pkt1},
#                                  {'port': 2, 'packet': exp_pkt2}],
#                                 cap_pkts, input_ports)
#    output = sstf.check_out_pkts([{'port': 2, 'packet': exp_pkt1},
#                                  {'port': 3, 'packet': exp_pkt3}],
#    output = sstf.check_out_pkts([{'port': 2, 'packet': exp_pkt1},
#                                  {'port': 2, 'packet': exp_pkt2},
#                                  {'port': 3, 'packet': exp_pkt3},
#                                  {'port': 4, 'packet': exp_pkt2}],
#                                 cap_pkts, input_ports)

    return output


def test_mtu_failing(hdl, port_int_map, exp_src_mac, exp_dst_mac, port_mtu):
    """Forward IPv4 unicast packets that are barely small enough to fit
    within the output interface MTU, and barely too large to fit,
    and are thus dropped by the current P4 program."""

    # Subtract 14 for Ethernet header, 20 for IPv4 header without
    # options, and another 20 for TCP header without options.
    port_2_tcp_payload_mtu = port_mtu[2] - 14 - 20 - 20
    port_3_tcp_payload_mtu = port_mtu[3] - 14 - 20 - 20
    fwd_pkt1 = (Ether() / IP(dst='10.1.0.1') / TCP(sport=5793, dport=80) /
                Raw("a" * port_2_tcp_payload_mtu))
    drop_pkt1a = (Ether() / IP(dst='10.1.0.1') / TCP(sport=5793, dport=80) /
                  Raw("a" * (port_2_tcp_payload_mtu + 1)))
    drop_pkt1b = (Ether() / IP(dst='10.1.0.1') / TCP(sport=5793, dport=80) /
                  Raw("a" * (port_2_tcp_payload_mtu + 100)))
    fwd_pkt2 = (Ether() / IP(dst='10.1.0.32') / TCP(sport=5793, dport=80) /
                Raw("a" * port_3_tcp_payload_mtu))
    drop_pkt2 = (Ether() / IP(dst='10.1.0.32') / TCP(sport=5793, dport=80) /
                 Raw("a" * (port_3_tcp_payload_mtu + 1)))

    exp_pkt1 = update_macs_dec_ipv4_ttl(fwd_pkt1, exp_src_mac, exp_dst_mac)
    exp_pkt2 = update_macs_dec_ipv4_ttl(fwd_pkt2, exp_src_mac, exp_dst_mac)

    cap_pkts = sstf.send_pkts_and_capture(port_int_map,
                                          [{'port': 0, 'packet': fwd_pkt1},
                                           {'port': 0, 'packet': drop_pkt1a},
                                           {'port': 1, 'packet': drop_pkt1b},
                                           {'port': 1, 'packet': fwd_pkt2},
                                           {'port': 1, 'packet': drop_pkt2}])
    input_ports = {0, 1}
    output = sstf.check_out_pkts([{'port': 2, 'packet': exp_pkt1},
                                  {'port': 3, 'packet': exp_pkt2}],
                                 cap_pkts, input_ports)
    return output


def test_ttl_cases(hdl, port_int_map, exp_src_mac, exp_dst_mac):
    """IPv4 unicast forwarding cases where several packets are dropped
    because their TTL is 0 or 1."""

    # fwd_pkt1 will be forwarded normally, but the other two should be
    # dropped.
    fwd_pkt1 = Ether() / IP(dst='10.1.0.1') / TCP(sport=5793, dport=80)
    fwd_pkt2 = Ether() / IP(dst='10.1.0.34', ttl=1) / TCP(sport=5793, dport=80)
    fwd_pkt3 = Ether() / IP(dst='10.1.0.32', ttl=0) / TCP(sport=5793, dport=80)

    exp_pkt1 = update_macs_dec_ipv4_ttl(fwd_pkt1, exp_src_mac, exp_dst_mac)

    cap_pkts = sstf.send_pkts_and_capture(port_int_map,
                                          [{'port': 0, 'packet': fwd_pkt1},
                                           {'port': 1, 'packet': fwd_pkt2},
                                           {'port': 1, 'packet': fwd_pkt3}])
    input_ports = {0, 1}
    output = sstf.check_out_pkts([{'port': 2, 'packet': exp_pkt1}],
                                 cap_pkts, input_ports)
    return output


def table_entries_multicast(hdl, exp_src_mac):
    """Add some table entries useful for testing some IPv4 multicast
    forwarding code."""

    hdl.do_table_add("%smcgp_sa_da_lookup %sset_mc_group 10.1.0.3 224.1.0.1 => 2 0 0 1" % (ipfx, ipfx))
    hdl.do_table_add("%smcgp_da_lookup %sset_mc_group 224.1.0.1 => 3 1 0 2" % (ipfx, ipfx))

    hdl.do_table_add("%smcgp_bidirect %sset_bdir_map 0 1 => 1" % (ipfx, ipfx))
    hdl.do_table_add("%smcgp_bidirect %sset_bdir_map 1 2 => 1" % (ipfx, ipfx))

    hdl.do_mc_mgrp_create("2")
    hdl.do_mc_mgrp_create("3")
    mc_node_value1 = hdl.do_mc_node_create("12 2 3")
    mc_node_value2 = hdl.do_mc_node_create("24 4 5 6")

    node_handle1 = "2 " + str(mc_node_value1)
    node_handle2 = "3 " + str(mc_node_value2)

    hdl.do_mc_node_associate(node_handle1)
    hdl.do_mc_node_associate(node_handle2)

    hdl.do_table_add("%sport_bd_rid %sout_bd_port_match 2 12 => 10" % (epfx, epfx))
    hdl.do_table_add("%sport_bd_rid %sout_bd_port_match 3 12 => 11" % (epfx, epfx))
    hdl.do_table_add("%sport_bd_rid %sout_bd_port_match 4 24 => 12" % (epfx, epfx))
    hdl.do_table_add("%sport_bd_rid %sout_bd_port_match 5 24 => 13" % (epfx, epfx))
    hdl.do_table_add("%sport_bd_rid %sout_bd_port_match 6 24 => 14" % (epfx, epfx))

    hdl.do_table_add("%smtu_check %sassign_mtu 10 => 400" % (epfx, epfx))
    hdl.do_table_add("%smtu_check %sassign_mtu 11 => 400" % (epfx, epfx))
    hdl.do_table_add("%smtu_check %sassign_mtu 12 => 400" % (epfx, epfx))
    hdl.do_table_add("%smtu_check %sassign_mtu 13 => 400" % (epfx, epfx))
    hdl.do_table_add("%smtu_check %sassign_mtu 14 => 400" % (epfx, epfx))

    hdl.do_table_add("%ssend_frame %srewrite_mac 10 => %s" % (epfx, epfx, exp_src_mac))
    hdl.do_table_add("%ssend_frame %srewrite_mac 11 => %s" % (epfx, epfx, exp_src_mac))
    hdl.do_table_add("%ssend_frame %srewrite_mac 12 => %s" % (epfx, epfx, exp_src_mac))
    hdl.do_table_add("%ssend_frame %srewrite_mac 13 => %s" % (epfx, epfx, exp_src_mac))
    hdl.do_table_add("%ssend_frame %srewrite_mac 14 => %s" % (epfx, epfx, exp_src_mac))


def test_multicast_sa_da(hdl, port_int_map, exp_src_mac):
    """IPv4 multicast forwarding cases where packets are forwarded
    normally, with replication to multiple output ports, without
    dropping."""

    fwd_pkt1 = (Ether() / IP(src='10.1.0.3', dst='224.1.0.1') /
                TCP(sport=5793, dport=80))
    fwd_pkt2 = (Ether() / IP(src='10.1.0.5', dst='224.1.0.1') /
                TCP(sport=5793, dport=80))

    # Note: At least for now, the P4 program being tested does not
    # correctly modify the Ethernet destination MAC address, but
    # leaves it unchanged.
    exp_pkt1 = update_macs_dec_ipv4_ttl(fwd_pkt1, exp_src_mac)
    exp_pkt2 = update_macs_dec_ipv4_ttl(fwd_pkt2, exp_src_mac)

    cap_pkts = sstf.send_pkts_and_capture(port_int_map,
                                          [{'port': 0, 'packet': fwd_pkt1},
                                           {'port': 1, 'packet': fwd_pkt2}])
    input_ports = {0, 1}
    output = sstf.check_out_pkts([{'port': 2, 'packet': exp_pkt1},
                                  {'port': 3, 'packet': exp_pkt1},
                                  {'port': 4, 'packet': exp_pkt2},
                                  {'port': 5, 'packet': exp_pkt2},
                                  {'port': 6, 'packet': exp_pkt2}],
                                 cap_pkts, input_ports)
    return output


def test_multicast_rpf(hdl, port_int_map, exp_src_mac):
    """IPv4 multicast forwarding cases where packets are dropped because
    they arriv on an input port that is not one that the multicast
    route they match allows to be forwarded -- the multicast RPF
    check fails."""

    fwd_pkt1 = (Ether() / IP(src='10.1.0.3', dst='224.1.0.1') /
                TCP(sport=5793, dport=80))
    fwd_pkt2 = (Ether() / IP(src='10.1.0.5', dst='224.1.0.1') /
                TCP(sport=5793, dport=80))

    # These input packets should be dropped by the multicast RPF check
    # in the P4 program, so no need to create expected output packets.

    # The ports 1 and 0 are exchanged to check that the rpf and
    # ingress port are different, thus dropping the packets
    cap_pkts = sstf.send_pkts_and_capture(port_int_map,
                                          [{'port': 1, 'packet': fwd_pkt1},
                                           {'port': 0, 'packet': fwd_pkt2}])
    input_ports = {0, 1}
    output = sstf.check_out_pkts([], cap_pkts, input_ports)
    return output


def main():
    '''main block '''

    # port_int_map represents the desired correspondence between P4
    # program port numbers and Linux interfaces.  The data structure
    # returned by port_intf_mapping() is used in multiple places
    # throughout the code.
    port_int_map = sstf.port_intf_mapping({0: 'veth2',
                                           1: 'veth4',
                                           2: 'veth6',
                                           3: 'veth8',
                                           4: 'veth10',
                                           5: 'veth12',
                                           6: 'veth14'})
    args = sstf.get_args()
    ss_process_obj = sstf.start_simple_switch(args, port_int_map)
    hdl = runtime_CLI.test_init(args)

    exp_src_mac = "00:11:22:33:44:55"
    exp_dst_mac = "02:13:57:ab:cd:ef"

    port_mtu = [1518, 1518, 400, 1518]
    table_entries_unicast(hdl, exp_src_mac, exp_dst_mac, port_mtu)
    table_entries_multicast(hdl, exp_src_mac)

    output1 = test_mtu_regular(hdl, port_int_map, exp_src_mac, exp_dst_mac)
    print(output1)
    output2 = test_mtu_failing(hdl, port_int_map, exp_src_mac, exp_dst_mac,
                               port_mtu)
    print(output2)
    output3 = test_ttl_cases(hdl, port_int_map, exp_src_mac, exp_dst_mac)
    print(output3)
    output4 = test_multicast_sa_da(hdl, port_int_map, exp_src_mac)
    print(output4)
    output5 = test_multicast_rpf(hdl, port_int_map, exp_src_mac)
    print(output5)

    ss_process_obj.kill()


if __name__ == '__main__':
    main()
