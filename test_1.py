#!/usr/bin/env python2

''' test case for P4 '''

from __future__ import print_function
import subprocess
from scapy.all import *
from scapy.all import TCP, Ether, IP
from runtime_CLI import test_init, get_parser, PreType
import sstf_lib as sstf


def table_entries_unicast(hdl, exp_src_mac, exp_dst_mac):

    hdl.do_table_add("ipv4_da_lpm set_l2ptr 10.1.0.1/32 => 58")
    hdl.do_table_add("ipv4_da_lpm set_l2ptr 10.1.0.34/32 => 58")
    hdl.do_table_add("ipv4_da_lpm set_l2ptr 10.1.0.32/32 => 45")
    hdl.do_table_add("mac_da set_bd_dmac_intf 58 => 9 " + exp_dst_mac + " 2")
    hdl.do_table_add("mac_da set_bd_dmac_intf 45 => 7 " + exp_dst_mac + " 3")
    hdl.do_table_add("send_frame rewrite_mac 9 => " + exp_src_mac)
    hdl.do_table_add("send_frame rewrite_mac 7 => " + exp_src_mac)
    hdl.do_table_add("mtu_check assign_mtu 9 => 400")
    hdl.do_table_add("mtu_check assign_mtu 7 => 400")


def test_mtu_regular(hdl, port_int_map, exp_src_mac, exp_dst_mac):

    tcp_payload = "a" * 80
    fwd_pkt1 = Ether() / IP(dst='10.1.0.1') / TCP(sport=5793, dport=80)
    fwd_pkt2 = Ether() / IP(dst='10.1.0.34') / TCP(sport=5793, dport=80)
    fwd_pkt3 = (Ether() / IP(dst='10.1.0.32') / TCP(sport=5793, dport=80) /
                Raw(tcp_payload))

    exp_pkt1 = (Ether(src=exp_src_mac, dst=exp_dst_mac) /
                IP(dst='10.1.0.1', ttl=fwd_pkt1[IP].ttl-1) /
                TCP(sport=5793, dport=80))
    exp_pkt2 = (Ether(src=exp_src_mac, dst=exp_dst_mac) /
                IP(dst='10.1.0.34', ttl=fwd_pkt2[IP].ttl-1) /
                TCP(sport=5793, dport=80))
    exp_pkt3 = (Ether(src=exp_src_mac, dst=exp_dst_mac) /
                IP(dst='10.1.0.32', ttl=fwd_pkt3[IP].ttl-1) /
                TCP(sport=5793, dport=80) / Raw(tcp_payload))
    pack = sstf.send_pkts_and_capture(port_int_map,
                                      [{'port': 0, 'packet': fwd_pkt1},
                                       {'port': 1, 'packet': fwd_pkt2},
                                       {'port': 1, 'packet': fwd_pkt3}])
    input_ports = {0, 1}
    output = sstf.check_out_pkts([{'port': 2, 'packet': exp_pkt1},
                                  {'port': 2, 'packet': exp_pkt2},
                                  {'port': 3, 'packet': exp_pkt3}],
                                 pack, input_ports)
    return output


def test_mtu_failing(hdl, port_int_map, exp_src_mac, exp_dst_mac):

    tcp_payload = "a" * 80
    fwd_pkt1 = Ether() / IP(dst='10.1.0.1') / TCP(sport=5793, dport=80)
    fwd_pkt2 = Ether() / IP(dst='10.1.0.34') / TCP(sport=5793, dport=80)
    fwd_pkt3 = (Ether() / IP(dst='10.1.0.32') / TCP(sport=5793, dport=80) /
                Raw(tcp_payload))

    exp_pkt1 = (Ether(src=exp_src_mac, dst=exp_dst_mac) /
                IP(dst='10.1.0.1', ttl=fwd_pkt1[IP].ttl-1) /
                TCP(sport=5793, dport=80))
    exp_pkt2 = (Ether(src=exp_src_mac, dst=exp_dst_mac) /
                IP(dst='10.1.0.34', ttl=fwd_pkt2[IP].ttl-1) /
                TCP(sport=5793, dport=80))
    exp_pkt3 = (Ether(src=exp_src_mac, dst=exp_dst_mac) /
                IP(dst='10.1.0.32', ttl=fwd_pkt3[IP].ttl-1) /
                TCP(sport=5793, dport=80) / Raw(tcp_payload))
    pack = sstf.send_pkts_and_capture(port_int_map,
                                      [{'port': 0, 'packet': fwd_pkt1},
                                       {'port': 1, 'packet': fwd_pkt2},
                                       {'port': 1, 'packet': fwd_pkt3}])
    input_ports = {0, 1}
    output = sstf.check_out_pkts([{'port': 2, 'packet': exp_pkt1},
                                  {'port': 2, 'packet': exp_pkt2},
                                  {'port': 3, 'packet': exp_pkt3}],
                                 pack, input_ports)
    return output


def test_ttl_cases(hdl, port_int_map, exp_src_mac, exp_dst_mac):

    fwd_pkt1 = Ether() / IP(dst='10.1.0.1') / TCP(sport=5793, dport=80)
    fwd_pkt2 = Ether() / IP(dst='10.1.0.34', ttl=1) / TCP(sport=5793, dport=80)
    fwd_pkt3 = Ether() / IP(dst='10.1.0.32', ttl=0) / TCP(sport=5793, dport=80)

    exp_pkt1 = (Ether(src=exp_src_mac, dst=exp_dst_mac) /
                IP(dst='10.1.0.1', ttl=fwd_pkt1[IP].ttl-1) /
                TCP(sport=5793, dport=80))

    pack = sstf.send_pkts_and_capture(port_int_map,
                                      [{'port': 0, 'packet': fwd_pkt1},
                                       {'port': 1, 'packet': fwd_pkt2},
                                       {'port': 1, 'packet': fwd_pkt3}])
    input_ports = {0, 1}
    output = sstf.check_out_pkts([{'port': 2, 'packet': exp_pkt1}],
                                 pack, input_ports)
    return output


def table_entries_multicast(hdl, exp_src_mac):

    hdl.do_table_add("mcgp_sa_da_lookup set_mc_group 10.1.0.3 224.1.0.1 => 2 0 0 1")
    hdl.do_table_add("mcgp_da_lookup set_mc_group 224.1.0.1 => 3 1 0 2")

    hdl.do_table_add("mcgp_bidirect set_bdir_map 0 1 => 1")
    hdl.do_table_add("mcgp_bidirect set_bdir_map 1 2 => 1")

    hdl.do_mc_mgrp_create("2")
    hdl.do_mc_mgrp_create("3")
    mc_node_value1 = hdl.do_mc_node_create("12 2 3")
    mc_node_value2 = hdl.do_mc_node_create("24 4 5 6")

    node_handle1 = "2 " + str(mc_node_value1)
    node_handle2 = "3 " + str(mc_node_value2)

    hdl.do_mc_node_associate(node_handle1)
    hdl.do_mc_node_associate(node_handle2)

    hdl.do_table_add("port_bd_rid out_bd_port_match 2 12 => 10")
    hdl.do_table_add("port_bd_rid out_bd_port_match 3 12 => 11")
    hdl.do_table_add("port_bd_rid out_bd_port_match 4 24 => 12")
    hdl.do_table_add("port_bd_rid out_bd_port_match 5 24 => 13")
    hdl.do_table_add("port_bd_rid out_bd_port_match 6 24 => 14")

    hdl.do_table_add("mtu_check assign_mtu 10 => 400")
    hdl.do_table_add("mtu_check assign_mtu 11 => 400")
    hdl.do_table_add("mtu_check assign_mtu 12 => 400")
    hdl.do_table_add("mtu_check assign_mtu 13 => 400")
    hdl.do_table_add("mtu_check assign_mtu 14 => 400")

    hdl.do_table_add("send_frame rewrite_mac 10 => " + exp_src_mac)
    hdl.do_table_add("send_frame rewrite_mac 11 => " + exp_src_mac)
    hdl.do_table_add("send_frame rewrite_mac 12 => " + exp_src_mac)
    hdl.do_table_add("send_frame rewrite_mac 13 => " + exp_src_mac)
    hdl.do_table_add("send_frame rewrite_mac 14 => " + exp_src_mac)


def test_multicast_sa_da(hdl, port_int_map, exp_src_mac, exp_dst_mac):

    fwd_pkt1 = (Ether() / IP(src='10.1.0.3', dst='224.1.0.1') /
                TCP(sport=5793, dport=80))
    fwd_pkt2 = (Ether() / IP(src='10.1.0.5', dst='224.1.0.1') /
                TCP(sport=5793, dport=80))

    exp_pkt1 = (Ether(src=exp_src_mac) /
                IP(src='10.1.0.3', dst='224.1.0.1', ttl=fwd_pkt1[IP].ttl-1) /
                TCP(sport=5793, dport=80))
    exp_pkt2 = (Ether(src=exp_src_mac) /
                IP(src='10.1.0.5', dst='224.1.0.1', ttl=fwd_pkt2[IP].ttl-1) /
                TCP(sport=5793, dport=80))

    pack = sstf.send_pkts_and_capture(port_int_map,
                                      [{'port': 0, 'packet': fwd_pkt1},
                                       {'port': 1, 'packet': fwd_pkt2}])
    input_ports = {0, 1}
    output = sstf.check_out_pkts([{'port': 2, 'packet': exp_pkt1},
                                  {'port': 3, 'packet': exp_pkt1},
                                  {'port': 4, 'packet': exp_pkt2},
                                  {'port': 5, 'packet': exp_pkt2},
                                  {'port': 6, 'packet': exp_pkt2}],
                                 pack, input_ports)
    return output


def test_multicast_rpf(hdl, port_int_map, exp_src_mac, exp_dst_mac):

    fwd_pkt1 = (Ether() / IP(src='10.1.0.3', dst='224.1.0.1') /
                TCP(sport=5793, dport=80))
    fwd_pkt2 = (Ether() / IP(src='10.1.0.5', dst='224.1.0.1') /
                TCP(sport=5793, dport=80))

    exp_pkt1 = (Ether(src=exp_src_mac) /
                IP(src='10.1.0.3', dst='224.1.0.1', ttl=fwd_pkt1[IP].ttl-1) /
                TCP(sport=5793, dport=80))
    exp_pkt2 = (Ether(src=exp_src_mac) /
                IP(src='10.1.0.5', dst='224.1.0.1', ttl=fwd_pkt2[IP].ttl-1) /
                TCP(sport=5793, dport=80))
    # The ports 1 nad 0 are exchanged to check that the rpf and
    # ingress port are different , thus dropping the packets
    pack = sstf.send_pkts_and_capture(port_int_map,
                                      [{'port': 1, 'packet': fwd_pkt1},
                                       {'port': 0, 'packet': fwd_pkt2}])
    input_ports = {0, 1}
    output = sstf.check_out_pkts([], pack, input_ports)
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
    
    args = get_parser().parse_args()
    args.pre = PreType.SimplePreLAG
    
    #print('args.thrift_port=%s' % (args.thrift_port))
    #print('args.thrift_ip=%s' % (args.thrift_ip))
    #print('args.json=%s' % (args.json))
    #print('args.pre=%s' % (args.pre))
    #print('PreType.SimplePre=%s' % (PreType.SimplePre))
    #print('PreType.SimplePreLAG=%s' % (PreType.SimplePreLAG))

    # When running tests repeatedly, it sometimes happens that the
    # test script dies due to raising some exception, without getting
    # to the end and killing the simple_switch child process.  To help
    # avoid confusion, kill any existing simple_switch processes
    # before proceeding.
    log_file_base_name = "log_file_data"
    log_file_full_name = log_file_base_name + ".txt"
    subprocess.call(["killall", "simple_switch"])
    try:
        os.remove(log_file_full_name)
    except OSError:
        print("Got exception OSError trying to do os.remove() on a file,"
              " probably because there is no such file.  Continuing.")

    ss_cmd_and_args = (["simple_switch",
                        "--log-file", log_file_base_name,
                        "--log-flush",
                        "--thrift-port", str(args.thrift_port)] +
                       sstf.ss_interface_args(port_int_map) +
                       [args.json])
    ss_obj = subprocess.Popen(ss_cmd_and_args)

    time.sleep(2)
    hdl = test_init(args)

    exp_src_mac = "00:11:22:33:44:55"
    exp_dst_mac = "02:13:57:ab:cd:ef"

    table_entries_unicast(hdl, exp_src_mac, exp_dst_mac)
    table_entries_multicast(hdl, exp_src_mac)

    output1 = test_mtu_regular(hdl, port_int_map, exp_src_mac, exp_dst_mac)
    print(output1)
    output2 = test_mtu_failing(hdl, port_int_map, exp_src_mac, exp_dst_mac)
    print(output2)
    output3 = test_ttl_cases(hdl, port_int_map, exp_src_mac, exp_dst_mac)
    print(output3)
    output4 = test_multicast_sa_da(hdl, port_int_map, exp_src_mac, exp_dst_mac)
    print(output4)
    output5 = test_multicast_rpf(hdl, port_int_map, exp_src_mac, exp_dst_mac)
    print(output5)

    ss_obj.kill()


if __name__ == '__main__':
    main()
