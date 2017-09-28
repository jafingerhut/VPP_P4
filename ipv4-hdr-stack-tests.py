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


def eth_hdr_only(pkt_with_port):
    ret = copy.deepcopy(pkt_with_port)
    ret['packet'] = Ether(str(pkt_with_port['packet'])[0:14])
    return ret


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
        

def create_exp_pkt(input_pkt, input_valid_vector, my_action):
    input_pkt_str = str(input_pkt)
    eth_str = input_pkt_str[0:14]
    ip_hdr_strs = []
    offset = 14
    for i in range(4):
        if input_valid_vector[i] == 1:
            ip_hdr_strs.append(input_pkt_str[offset:offset+20])
            offset += 20
        else:
            ip_hdr_strs.append("")
    rest_of_pkt_str = input_pkt_str[offset:]

    if my_action == 'my_nop':
        op = 'nop'
    elif my_action == 'add_hdr0':
        op = 'add'
        pos = 0
    elif my_action == 'add_hdr1':
        op = 'add'
        pos = 1
    elif my_action == 'add_hdr2':
        op = 'add'
        pos = 2
    elif my_action == 'add_hdr3':
        op = 'add'
        pos = 3
    elif my_action == 'rm_hdr0':
        op = 'rm'
        pos = 0
    elif my_action == 'rm_hdr1':
        op = 'rm'
        pos = 1
    elif my_action == 'rm_hdr2':
        op = 'rm'
        pos = 2
    elif my_action == 'rm_hdr3':
        op = 'rm'
        pos = 3
    if op == 'add':
        tmp_pkt = (Ether() / IP(len=20, id=0, ttl=64+pos, proto=4, chksum=0,
                                src='250.206.0.%d' % (pos), dst='0.0.0.0'))
        ip_hdr_strs[pos] = str(tmp_pkt)[14:14+20]
    elif op == 'rm':
        ip_hdr_strs[pos] = ""

    exp_pkt_str = eth_str
    for i in range(4):
        exp_pkt_str += ip_hdr_strs[i]
    exp_pkt_str += rest_of_pkt_str
    exp_pkt = Ether(exp_pkt_str)
    exp_pkt2 = update_dbg_fields(exp_pkt, input_valid_vector,
                                 update_stack_valid(input_valid_vector,
                                                    my_action))
    return exp_pkt2


def test_one_hdr_op(hdl, port_int_map, my_action):
    hdl.do_table_set_default("ipv4_da_lpm %s" % (my_action))
    fwd_pkt1 = Ether() / IP(dst='10.1.0.1') / TCP(sport=5793, dport=80)
    fwd_pkt2 = Ether() / IP(dst='10.1.0.1') / IP() / TCP(sport=5793, dport=80)
    fwd_pkt3 = Ether() / IP(dst='10.1.0.1') / IP() / IP() / TCP(sport=5793, dport=80)
    fwd_pkt4 = Ether() / IP(dst='10.1.0.1') / IP() / IP() / IP() / TCP(sport=5793, dport=80)

    exp_pkt1 = create_exp_pkt(fwd_pkt1, [1, 0, 0, 0], my_action)
    exp_pkt2 = create_exp_pkt(fwd_pkt2, [1, 1, 0, 0], my_action)
    exp_pkt3 = create_exp_pkt(fwd_pkt3, [1, 1, 1, 0], my_action)
    exp_pkt4 = create_exp_pkt(fwd_pkt4, [1, 1, 1, 1], my_action)

    cap_pkts = sstf.send_pkts_and_capture(port_int_map,
                                          [
                                              {'port': 0, 'packet': fwd_pkt1},
                                              {'port': 0, 'packet': fwd_pkt2},
                                              {'port': 0, 'packet': fwd_pkt3},
                                              {'port': 0, 'packet': fwd_pkt4}
                                          ])
    input_ports = {0}

    exp_pkts = [
        {'port': 1, 'packet': exp_pkt1},
        {'port': 1, 'packet': exp_pkt2},
        {'port': 1, 'packet': exp_pkt3},
        {'port': 1, 'packet': exp_pkt4}
    ]
    output = sstf.check_out_pkts(exp_pkts, cap_pkts, input_ports)

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
