#!/usr/bin/env python2

'''Test cases for P4 program ipv4-hdr-stacks (both P4_14 and P4_16 version, hopefully)'''

from __future__ import print_function
from scapy.all import *
# The following line isn't really necessary given the previous import
# line, but it does help avoid many 'undefined variable' pylint
# warnings
from scapy.all import TCP, Ether, IP
import runtime_CLI
import sstf_lib as sstf


def table_entries1(hdl):
    """Add some table entries useful for testing some IPv4 unicast
    forwarding code."""

    hdl.do_table_set_default("set_output_port set_egress_spec_1")
    hdl.do_table_set_default("debug_ipv4_hdr_stack1 set_debug_fld1")
    hdl.do_table_set_default("clear_stack_valid_vector1 clear_stack_valid_vector_action")
    hdl.do_table_set_default("set_bit_0_of_stack_valid_vector1 set_bit_0_of_stack_valid_vector_action")
    hdl.do_table_set_default("set_bit_1_of_stack_valid_vector1 set_bit_1_of_stack_valid_vector_action")
    hdl.do_table_set_default("set_bit_2_of_stack_valid_vector1 set_bit_2_of_stack_valid_vector_action")
    hdl.do_table_set_default("set_bit_3_of_stack_valid_vector1 set_bit_3_of_stack_valid_vector_action")
    hdl.do_table_set_default("debug_ipv4_hdr_stack2 set_debug_fld2")
    hdl.do_table_set_default("clear_stack_valid_vector2 clear_stack_valid_vector_action")
    hdl.do_table_set_default("set_bit_0_of_stack_valid_vector2 set_bit_0_of_stack_valid_vector_action")
    hdl.do_table_set_default("set_bit_1_of_stack_valid_vector2 set_bit_1_of_stack_valid_vector_action")
    hdl.do_table_set_default("set_bit_2_of_stack_valid_vector2 set_bit_2_of_stack_valid_vector_action")
    hdl.do_table_set_default("set_bit_3_of_stack_valid_vector2 set_bit_3_of_stack_valid_vector_action")


def bit_list_to_int(bit_list):
    ret = 0
    bit_pos = 0
    for bit_val in bit_list:
        assert isinstance(bit_val, int)
        assert bit_val == 0 or bit_val == 1
        ret |= (bit_val << bit_pos)
        bit_pos += 1
    return ret


def update_dbg_fields(pkt_in, valid_vec_parsed, valid_vec_deparsed):
    new_pkt = pkt_in.copy()
    assert len(valid_vec_parsed) == 4
    assert len(valid_vec_deparsed) == 4
    #print('src %s' % (new_pkt[Ether].src))
    #print('src[-2:] %s' % (new_pkt[Ether].src[-2:]))
    #print('src[:-2] %s' % (new_pkt[Ether].src[:-2]))
    new_pkt[Ether].src = (new_pkt[Ether].src[:-2] +
                          '%02x' % (bit_list_to_int(valid_vec_parsed)))
    new_pkt[Ether].dst = (new_pkt[Ether].dst[:-2] +
                          '%02x' % (bit_list_to_int(valid_vec_deparsed)))
    return new_pkt


def test_case1(hdl, port_int_map):

    hdl.do_table_set_default("ipv4_da_lpm my_nop")
    fwd_pkt1 = Ether() / IP(dst='10.1.0.1') / TCP(sport=5793, dport=80)
    fwd_pkt2 = Ether() / IP(dst='10.1.0.1') / IP() / TCP(sport=5793, dport=80)
    fwd_pkt3 = Ether() / IP(dst='10.1.0.1') / IP() / IP() / TCP(sport=5793, dport=80)
    #print('fwd_pkt1 %s' % (sstf.byte_to_hex(str(fwd_pkt1))))
    #print('fwd_pkt2 %s' % (sstf.byte_to_hex(str(fwd_pkt2))))
    #print('fwd_pkt3 %s' % (sstf.byte_to_hex(str(fwd_pkt3))))

    exp_pkt1 = update_dbg_fields(fwd_pkt1, [1, 0, 0, 0], [1, 0, 0, 0])
    exp_pkt2 = update_dbg_fields(fwd_pkt2, [1, 1, 0, 0], [1, 1, 0, 0])
    exp_pkt3 = update_dbg_fields(fwd_pkt3, [1, 1, 1, 0], [1, 1, 1, 0])

    cap_pkts = sstf.send_pkts_and_capture(port_int_map,
                                          [{'port': 0, 'packet': fwd_pkt1},
                                           {'port': 0, 'packet': fwd_pkt2},
                                           {'port': 0, 'packet': fwd_pkt3}])
    input_ports = {0}
    output = sstf.check_out_pkts([{'port': 1, 'packet': exp_pkt1},
                                  {'port': 1, 'packet': exp_pkt2},
                                  {'port': 1, 'packet': exp_pkt3}],
                                 cap_pkts, input_ports)

    return output


def eth_hdr_only(pkt_with_port):
    ret = copy.deepcopy(pkt_with_port)
    ret['packet'] = Ether(str(pkt_with_port['packet'])[0:14])
    return ret


def test_add_hdr0(hdl, port_int_map):
    hdl.do_table_set_default("ipv4_da_lpm add_hdr0")
    fwd_pkt1 = Ether() / IP(dst='10.1.0.1') / TCP(sport=5793, dport=80)
    fwd_pkt2 = Ether() / IP(dst='10.1.0.1') / IP() / TCP(sport=5793, dport=80)
    fwd_pkt3 = Ether() / IP(dst='10.1.0.1') / IP() / IP() / TCP(sport=5793, dport=80)
    fwd_pkt4 = Ether() / IP(dst='10.1.0.1') / IP() / IP() / IP() / TCP(sport=5793, dport=80)

    exp_pkt1 = update_dbg_fields(fwd_pkt1, [1, 0, 0, 0], [1, 0, 0, 0])
    exp_pkt2 = update_dbg_fields(fwd_pkt2, [1, 1, 0, 0], [1, 1, 0, 0])
    exp_pkt3 = update_dbg_fields(fwd_pkt3, [1, 1, 1, 0], [1, 1, 1, 0])
    exp_pkt4 = update_dbg_fields(fwd_pkt4, [1, 1, 1, 1], [1, 1, 1, 1])

    cap_pkts = sstf.send_pkts_and_capture(port_int_map,
                                          [{'port': 0, 'packet': fwd_pkt1},
                                           {'port': 0, 'packet': fwd_pkt2},
                                           {'port': 0, 'packet': fwd_pkt3},
                                           {'port': 0, 'packet': fwd_pkt4}])
    input_ports = {0}

    # Don't bother trying to check every byte of the output packet.
    # Focus on the least significant 4 bits of the Ethernet source and
    # dest addresses.
    cap_pkts_eth_only = [eth_hdr_only(p) for p in cap_pkts]
    exp_pkts = [{'port': 1, 'packet': exp_pkt1},
                {'port': 1, 'packet': exp_pkt2},
                {'port': 1, 'packet': exp_pkt3},
                {'port': 1, 'packet': exp_pkt4}]
    exp_pkts_eth_only = [eth_hdr_only(p) for p in exp_pkts]

    output = sstf.check_out_pkts(exp_pkts_eth_only,
                                 cap_pkts_eth_only, input_ports)

    return output


def update_stack_valid(stack_valid_list, my_action):
    ret = copy.copy(stack_valid_list)
    if my_action == 'my_nop':
        pass
    elif my_action == 'add_hdr0':
        ret[0] = 1
    elif my_action == 'add_hdr1':
        ret[1] = 1
    elif my_action == 'add_hdr2':
        ret[2] = 1
    elif my_action == 'add_hdr3':
        ret[3] = 1
    elif my_action == 'rm_hdr0':
        ret[0] = 0
    elif my_action == 'rm_hdr1':
        ret[1] = 0
    elif my_action == 'rm_hdr2':
        ret[2] = 0
    elif my_action == 'rm_hdr3':
        ret[3] = 0
    return ret
        

def test_one_hdr_op(hdl, port_int_map, my_action):
    hdl.do_table_set_default("ipv4_da_lpm %s" % (my_action))
    fwd_pkt1 = Ether() / IP(dst='10.1.0.1') / TCP(sport=5793, dport=80)
    fwd_pkt2 = Ether() / IP(dst='10.1.0.1') / IP() / TCP(sport=5793, dport=80)
    fwd_pkt3 = Ether() / IP(dst='10.1.0.1') / IP() / IP() / TCP(sport=5793, dport=80)
    fwd_pkt4 = Ether() / IP(dst='10.1.0.1') / IP() / IP() / IP() / TCP(sport=5793, dport=80)

    exp_pkt1 = update_dbg_fields(fwd_pkt1,
                                 [1, 0, 0, 0],
                                 update_stack_valid([1, 0, 0, 0], my_action))
    exp_pkt2 = update_dbg_fields(fwd_pkt2,
                                 [1, 1, 0, 0],
                                 update_stack_valid([1, 1, 0, 0], my_action))
    exp_pkt3 = update_dbg_fields(fwd_pkt3,
                                 [1, 1, 1, 0],
                                 update_stack_valid([1, 1, 1, 0], my_action))
    exp_pkt4 = update_dbg_fields(fwd_pkt4,
                                 [1, 1, 1, 1],
                                 update_stack_valid([1, 1, 1, 1], my_action))

    cap_pkts = sstf.send_pkts_and_capture(port_int_map,
                                          [
                                              {'port': 0, 'packet': fwd_pkt1},
                                              {'port': 0, 'packet': fwd_pkt2},
                                              {'port': 0, 'packet': fwd_pkt3},
                                              {'port': 0, 'packet': fwd_pkt4}
                                          ])
    input_ports = {0}

    # Don't bother trying to check every byte of the output packet.
    # Focus on the least significant 4 bits of the Ethernet source and
    # dest addresses.
    cap_pkts_eth_only = [eth_hdr_only(p) for p in cap_pkts]
    exp_pkts = [
        {'port': 1, 'packet': exp_pkt1},
        {'port': 1, 'packet': exp_pkt2},
        {'port': 1, 'packet': exp_pkt3},
        {'port': 1, 'packet': exp_pkt4}
    ]
    exp_pkts_eth_only = [eth_hdr_only(p) for p in exp_pkts]

    output = sstf.check_out_pkts(exp_pkts_eth_only,
                                 cap_pkts_eth_only, input_ports)

    return output


def main():
    '''main block '''

    # port_int_map represents the desired correspondence between P4
    # program port numbers and Linux interfaces.  The data structure
    # returned by port_intf_mapping() is used in multiple places
    # throughout the code.
    port_int_map = sstf.port_intf_mapping({0: 'veth2',
                                           1: 'veth4'})
    args = sstf.get_args()
    ss_process_obj = sstf.start_simple_switch(args, port_int_map)
    hdl = runtime_CLI.test_init(args)

    table_entries1(hdl)

    #output1 = test_case1(hdl, port_int_map)
    #print(output1)
    #output1 = test_add_hdr0(hdl, port_int_map)
    #print(output1)
    #output1 = test_add_hdr2(hdl, port_int_map)
    #print(output1)
    for hdr_op in ['my_nop',
                   'add_hdr0', 'add_hdr1', 'add_hdr2', 'add_hdr3',
                   'rm_hdr0', 'rm_hdr1', 'rm_hdr2', 'rm_hdr3' ]:
        print('')
        print('----- %s ------------------------------' % (hdr_op))
        output1 = test_one_hdr_op(hdl, port_int_map, hdr_op)
        print(output1)

    ss_process_obj.kill()


if __name__ == '__main__':
    main()
