#!/usr/bin/env python2
#import test_lib
''' test case for P4 '''
import Queue
import threading
from StringIO import StringIO
import sys
import argparse
import subprocess
import time
from scapy.all import *
from scapy.all import TCP, Ether, IP
from test_lib import RuntimeAPI, test_init, get_parser



def sniff_record(queue, port_interface_mapping):
    '''sniff record module : sniffs the queue for packets'''
    print "sniff start"
    pkt = sniff(timeout=3, iface=port_interface_mapping['intf_names'])
    #print pkt.show()
#    ip_src = packet[0].summary()
#    print ip_src
    print "sniff stop returned %d packet" %(len(pkt))
    #global pack
    #pack = packet
    queue.put(pkt)

def  pkt_str(pack):
    '''gets value from packet in the form of str '''
    old_stdout = sys.stdout
    sys.stdout = mystdout = StringIO()
    pack.show2()
    sys.stdout = old_stdout
    return mystdout.getvalue()

def byte_to_hex(byteStr):
    '''converts byte to hex '''
    return ''.join(["%02X " % ord(x) for x in byteStr]).strip()

def split_string(input_packet, expected_packet):
    '''splits the string and compares the expected and output pkt to find the difference. '''
    pack_in_len = len(input_packet)
    pack_out_len = len(expected_packet)
    if pack_in_len != pack_out_len:
        return "FAILED: Not same - packet lengths different"
    pack_in = input_packet.split()
    pack_out = expected_packet.split()
    list_len = len(pack_in)
    for i in range(list_len):
        if pack_in[i] != pack_out[i]:
            return ("FAILED: Expected packet was different at %s, compared to the packet"
                    " sniffed on port and was suppose to be %s"%(pack_out[i], pack_in[i]))
    return "equal"

def check_exp_outpkt(expected_packets, sniffed_pack, input_ports):
    ''' sniffs packet expected on output '''
    input_list = []
    #print "sniffed pack list len: %d" %(len(sniffed_pack))
    for j in sniffed_pack:
        num = j['port']
        #print num
        #ttl_check = j['packet'][IP].ttl
        if num in input_ports:
            continue
        else:
            input_list.append(j)

    sniffin_len = len(input_list)
    #print "sniffed output list: %d" %(sniffin_len)
    expected_len = len(expected_packets)
    if(sniffin_len < expected_len):
        range_len = sniffin_len
    else:
        range_len = expected_len
    #print list_len
    for i in range(range_len):
        input_packet = byte_to_hex(str(input_list[i]['packet']))
        expected_packet = byte_to_hex(str(expected_packets[i]['packet']))

        #print expected_packet
        exp_port = expected_packets[i]['port']
        in_port = input_list[i]['port']
        if(exp_port == in_port):
            result = split_string(input_packet, expected_packet)
            if result == "equal":
                #print "packet as expected"
                continue
            else:
                return result
        else:
            return "FAILED: Packet expected on a different port."
    if(sniffin_len == expected_len):
        return "All packets as expected"
    else:
        return "FAILED: Expected %d packets, but the packets sniffed out are %d"%(expected_len, sniffin_len)


def send_pkts_and_capture(port_interface_mapping, port_packet_list):
    ''' sends packets to P4 and captures by sniffing '''
    queue = Queue.Queue()
    #print len(port_packet_list)
    thd = threading.Thread(name="sniff_thread",
                           target=lambda: sniff_record(queue, port_interface_mapping))
    thd.start()
    #time.sleep(1)
    for x in port_packet_list:
        port_num = x['port']
        iface_name = port_interface_mapping['port2intf'][port_num]
        sendp(x['packet'], iface=iface_name)
    thd.join()
    pack = queue.get()
    #print "input packet list length: %d" %(len(pack))
    Packet_list = []
    for p in pack:
        eth = p.sniffed_on
        port_no = port_interface_mapping['intf_port_names'][eth]
        Packet_list.append({'port': port_no, 'packet': p})
    #print "all sniffed packets:%d" %(len(Packet_list))
    return Packet_list

def interfaceArgs(port_interface_mapping):
    ''' written to start simple switch every time program has to run '''
    result = []
    for port_int in port_interface_mapping['port2intf']:
        eth_name = port_interface_mapping['port2intf'][port_int]
        result.append("-i " + str(port_int) + "@" + eth_name)
    return result


def check_equality(p, exp_pkt1):
    ''' compares 2 packets - expected and packet which came '''
    if pkt_str(p['packet']) == pkt_str(exp_pkt1):
        return "equal"
    # elif pkt_str(p['packet']) == pkt_str(exp_pkt1):
      #  return "equal"
    else:
        return "not equal"

def port_intf_mapping(port2intf):

    port_interface_mapping = {
        'port2intf':port2intf
    }

    intf_names = []
    for port_num in port_interface_mapping['port2intf']:
        intf_names.append(port_interface_mapping['port2intf'][port_num])
    port_interface_mapping['intf_names'] = intf_names

    intf_port_map = {}

    for port_num in port_interface_mapping['port2intf']:
        intf_port_map[port_interface_mapping['port2intf'][port_num]] = port_num
    port_interface_mapping['intf_port_names'] = intf_port_map
    return port_interface_mapping

def test_mtu_regular(exp_src_mac, exp_dst_mac, port_interface_mapping, a, create_str):

    RuntimeAPI.do_table_add(a, "ipv4_da_lpm set_l2ptr 10.1.0.1/32 => 58")
    RuntimeAPI.do_table_add(a, "ipv4_da_lpm set_l2ptr 10.1.0.34/32 => 58")
    RuntimeAPI.do_table_add(a, "ipv4_da_lpm set_l2ptr 10.1.0.32/32 => 45")
    RuntimeAPI.do_table_add(a, "mac_da set_bd_dmac_intf 58 => 9 "+exp_dst_mac+" 2"+" 57")
    RuntimeAPI.do_table_add(a, "mac_da set_bd_dmac_intf 45 => 9 "+exp_dst_mac+" 3"+" 9000")
    RuntimeAPI.do_table_add(a, "send_frame rewrite_mac 9 => "+exp_src_mac)

    fwd_pkt1 = Ether() / IP(dst='10.1.0.1') / TCP(sport=5793, dport=80)
    fwd_pkt2 = Ether() / IP(dst='10.1.0.34') / TCP(sport=5793, dport=80)
    fwd_pkt3 = Ether() / IP(dst='10.1.0.32') / TCP(sport=5793, dport=80) / Raw(create_str)
#    fwd_pkt1=Ether() / IPv6(dst='127::1') / TCP(sport=5793, dport=80)
#    drop_pkt1=Ether() / IP(dst='10.1.0.34') / TCP(sport=5793, dport=80)
    exp_pkt1 = (Ether(src=exp_src_mac, dst=exp_dst_mac) /
                IP(dst='10.1.0.1', ttl=fwd_pkt1[IP].ttl-1) / TCP(sport=5793, dport=80))
    exp_pkt2 = (Ether(src=exp_src_mac, dst=exp_dst_mac) /
                IP(dst='10.1.0.34', ttl=fwd_pkt2[IP].ttl-1) / TCP(sport=5793, dport=80))
    exp_pkt3 = (Ether(src=exp_src_mac, dst=exp_dst_mac) /
                IP(dst='10.1.0.32', ttl=fwd_pkt3[IP].ttl-1) / TCP(sport=5793, dport=80) / Raw(create_str))
    pack = send_pkts_and_capture(port_interface_mapping, [{'port': 0, 'packet': fwd_pkt1},
                                                          {'port': 1, 'packet': fwd_pkt2},
                                                          {'port': 1, 'packet': fwd_pkt3}])
    input_ports = {0, 1}
    output = check_exp_outpkt([{'port': 2, 'packet': exp_pkt1},
                               {'port': 2, 'packet': exp_pkt2},
                               {'port': 3, 'packet': exp_pkt3}], pack, input_ports)
    return output

def test_mtu_failing(exp_src_mac, exp_dst_mac, port_interface_mapping, a, create_str):

    RuntimeAPI.do_table_add(a, "ipv4_da_lpm set_l2ptr 10.1.0.1/32 => 58")
    RuntimeAPI.do_table_add(a, "ipv4_da_lpm set_l2ptr 10.1.0.34/32 => 58")
    RuntimeAPI.do_table_add(a, "ipv4_da_lpm set_l2ptr 10.1.0.32/32 => 45")
    RuntimeAPI.do_table_add(a, "mac_da set_bd_dmac_intf 58 => 9 "+exp_dst_mac+" 2"+" 1514")
    RuntimeAPI.do_table_add(a, "mac_da set_bd_dmac_intf 45 => 9 "+exp_dst_mac+" 3"+" 9000")
    RuntimeAPI.do_table_add(a, "send_frame rewrite_mac 9 => "+exp_src_mac)

    fwd_pkt1 = Ether() / IP(dst='10.1.0.1') / TCP(sport=5793, dport=80)
    fwd_pkt2 = Ether() / IP(dst='10.1.0.34') / TCP(sport=5793, dport=80)
    fwd_pkt3 = Ether() / IP(dst='10.1.0.32') / TCP(sport=5793, dport=80) / Raw(create_str)
#    fwd_pkt1=Ether() / IPv6(dst='127::1') / TCP(sport=5793, dport=80)
#    drop_pkt1=Ether() / IP(dst='10.1.0.34') / TCP(sport=5793, dport=80)
    exp_pkt1 = (Ether(src=exp_src_mac, dst=exp_dst_mac) /
                IP(dst='10.1.0.1', ttl=fwd_pkt1[IP].ttl-1) / TCP(sport=5793, dport=80))
    exp_pkt2 = (Ether(src=exp_src_mac, dst=exp_dst_mac) /
                IP(dst='10.1.0.34', ttl=fwd_pkt2[IP].ttl-1) / TCP(sport=5793, dport=80))
    exp_pkt3 = (Ether(src=exp_src_mac, dst=exp_dst_mac) /
                IP(dst='10.1.0.32', ttl=fwd_pkt3[IP].ttl-1) / TCP(sport=5793, dport=80) / Raw(create_str))
    pack = send_pkts_and_capture(port_interface_mapping, [{'port': 0, 'packet': fwd_pkt1},
                                                          {'port': 1, 'packet': fwd_pkt2},
                                                          {'port': 1, 'packet': fwd_pkt3}])
    input_ports = {0, 1}
    output = check_exp_outpkt([{'port': 2, 'packet': exp_pkt1},
                               {'port': 2, 'packet': exp_pkt2},
                               {'port': 3, 'packet': exp_pkt3}], pack, input_ports)
    return output

def test_ttl_cases(exp_src_mac, exp_dst_mac, port_interface_mapping, a):
    #  Program test cases to check for ttl values- signed and unsigned
    RuntimeAPI.do_table_add(a, "ipv4_da_lpm set_l2ptr 10.1.0.1/32 => 58")
    RuntimeAPI.do_table_add(a, "ipv4_da_lpm set_l2ptr 10.1.0.34/32 => 58")
    RuntimeAPI.do_table_add(a, "ipv4_da_lpm set_l2ptr 10.1.0.32/32 => 45")
    RuntimeAPI.do_table_add(a, "mac_da set_bd_dmac_intf 58 => 9 "+exp_dst_mac+" 2"+" 56")
    RuntimeAPI.do_table_add(a, "mac_da set_bd_dmac_intf 45 => 9 "+exp_dst_mac+" 3"+" 9000")
    RuntimeAPI.do_table_add(a, "send_frame rewrite_mac 9 => "+exp_src_mac)

    fwd_pkt1 = Ether() / IP(dst='10.1.0.1') / TCP(sport=5793, dport=80)
    fwd_pkt2 = Ether() / IP(dst='10.1.0.34', ttl =1) / TCP(sport=5793, dport=80)
    fwd_pkt3 = Ether() / IP(dst='10.1.0.32', ttl=0) / TCP(sport=5793, dport=80)
    print len(IP(dst='10.1.0.1') / TCP(sport=5793, dport=80))
#    fwd_pkt1=Ether() / IPv6(dst='127::1') / TCP(sport=5793, dport=80)
#    drop_pkt1=Ether() / IP(dst='10.1.0.34') / TCP(sport=5793, dport=80)
    exp_pkt1 = (Ether(src=exp_src_mac, dst=exp_dst_mac) /
                IP(dst='10.1.0.1', ttl=fwd_pkt1[IP].ttl-1) / TCP(sport=5793, dport=80))

    pack = send_pkts_and_capture(port_interface_mapping, [{'port': 0, 'packet': fwd_pkt1},
                                                          {'port': 1, 'packet': fwd_pkt2},
                                                          {'port': 1, 'packet': fwd_pkt3}])
    input_ports = {0, 1}
    output = check_exp_outpkt([{'port': 2, 'packet': exp_pkt1}], pack, input_ports)
    #output = check_exp_outpkt([{'port': 2, 'packet': exp_pkt1},{'port': 2, 'packet': exp_pkt2}], pack, input_ports)
    return output

def main():
    '''main block '''
    parser = get_parser()
    args = parser.parse_args()
    # One time, construct a list of all ethernet interface names, which will be used
    # by future calls to sniff.
    port_interface_mapping=port_intf_mapping({0: 'veth2',
                                              1: 'veth4',
                                              2: 'veth6',
                                              3: 'veth8'})

    thriftPort = 9090
    # enter the name of the json file which will be created when we compile the P4 code.

    subprocess.call(["killall", "simple_switch"])
    os.remove("log_file_data.txt")

    runswitch = ["simple_switch", "--log-file", "log_file_data", "--log-flush", "--thrift-port",
                 str(thriftPort)] + interfaceArgs(port_interface_mapping) + [args.json]
    #print runswitch
    sw = subprocess.Popen(runswitch)

    time.sleep(2)

    a = test_init(args)
    exp_src_mac = "00:11:22:33:44:55"
    exp_dst_mac = "02:13:57:ab:cd:ef"
    n = 8000
    #create_str = "".join(choice(lowercase) for i in range(n))
    create_str = "a" * n
    #print create_str
    # RuntimeAPI.do_table_add(a, "ipv4_da_lpm set_l2ptr 10.1.0.1/32 => 58")
    # RuntimeAPI.do_table_add(a, "ipv4_da_lpm set_l2ptr 10.1.0.34/32 => 58")
    # RuntimeAPI.do_table_add(a, "ipv4_da_lpm set_l2ptr 10.1.0.32/32 => 45")
    # RuntimeAPI.do_table_add(a, "mac_da set_bd_dmac_intf 58 => 9 "+exp_dst_mac+" 2"+" 56")
    # RuntimeAPI.do_table_add(a, "mac_da set_bd_dmac_intf 45 => 9 "+exp_dst_mac+" 3"+" 9000")
    # RuntimeAPI.do_table_add(a, "send_frame rewrite_mac 9 => "+exp_src_mac)

    #output = test_mtu_regular(exp_src_mac, exp_dst_mac, port_interface_mapping, a, create_str)
    output = test_mtu_failing(exp_src_mac, exp_dst_mac, port_interface_mapping, a, create_str)
    #print "table entries: %s" %(output1) 
    #output = test_ttl_cases(exp_src_mac, exp_dst_mac, port_interface_mapping, a)
    print output

    sw.kill()


if __name__ == '__main__':
    main()