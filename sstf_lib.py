import collections
import Queue
from StringIO import StringIO
import time
import threading

from scapy.all import sniff, sendp



def port_intf_mapping(port2intf):
    port_int_map = {
        'port2intf':port2intf
    }

    # Calculate a list of Linux interface names.  Used later as an
    # argument to Scapy's sniff() method.
    intf_names = []
    for port_num in port_int_map['port2intf']:
        intf_names.append(port_int_map['port2intf'][port_num])
    port_int_map['intf_names'] = intf_names

    # Calculate a dict that maps Linux interface names to P4 program
    # port numbers.  Used later in send_pkts_and_capture() to
    # determine the P4 program port numbers of packets captured by
    # sniff().
    intf_port_map = {}
    for port_num in port_int_map['port2intf']:
        intf_port_map[port_int_map['port2intf'][port_num]] = port_num
    port_int_map['intf_port_names'] = intf_port_map

    return port_int_map


def ss_interface_args(port_int_map):
    '''Return list of strings which are the '-i' command line options to
    simple_switch process for the desired `port_int_map`.'''

    result = []
    for port_int in port_int_map['port2intf']:
        eth_name = port_int_map['port2intf'][port_int]
        result.append("-i")
        result.append(str(port_int) + "@" + eth_name)
    return result


def sniff_record(queue, port_int_map):
    '''sniff record module : sniffs the queue for packets'''
    print("sniff start")
    pkt = sniff(timeout=3, iface=port_int_map['intf_names'])
    print("sniff stop returned %d packet" % (len(pkt)))
    queue.put(pkt)


def send_pkts_and_capture(port_int_map, port_packet_list):
    '''Send packets in list `port_packet_list` to simple_switch
    process, while capturing packets sent to simple_switch, and
    output by simple_switch, by Scapy sniff() call.'''

    queue = Queue.Queue()
    thd = threading.Thread(name="sniff_thread",
                           target=lambda: sniff_record(queue, port_int_map))
    thd.start()

    # The time.sleep() call here gives time for thread 'thd' to start
    # sniffing packets, before we begin sending packets to the
    # simple_switch process immediately after that.
    time.sleep(1)

    for x in port_packet_list:
        port_num = x['port']
        iface_name = port_int_map['port2intf'][port_num]
        sendp(x['packet'], iface=iface_name)
    thd.join()
    pack = queue.get(True)
    Packet_list = []
    for p in pack:
        eth = p.sniffed_on
        port_no = port_int_map['intf_port_names'][eth]
        Packet_list.append({'port': port_no, 'packet': p})
    return Packet_list


def byte_to_hex(byteStr):
    '''converts byte to hex '''
    return ''.join(["%02X " % ord(x) for x in byteStr]).strip()


def print_packets(captured_pkt, expected_pkt):
    print("Captured Packet: %s" % (captured_pkt))
    print("Expected Packet: %s" % (expected_pkt))


def split_string(captured_pkt, expected_pkt):
    '''Splits the string and compares the expected and captured pkt to find
    the difference.'''

    captured_len = len(captured_pkt)
    expected_len = len(expected_pkt)
    if captured_len != expected_len:
        print_packets(captured_pkt, expected_pkt)
        return "FAILED: Not same - packet lengths different"
    captured_bytes = captured_pkt.split()
    expected_bytes = expected_pkt.split()
    # TBD: for loop below should stop at end of the shorter packet,
    # which might not be captured_pkt.
    list_len = len(captured_bytes)
    for i in range(list_len):
        if captured_bytes[i] != expected_bytes[i]:
            print_packets(captured_pkt, expected_pkt)
            return "different"
    return "equal"


def packets_by_port(pkt_lst, input_ports):
    pkts_by_port = collections.defaultdict(list)
    for j in pkt_lst:
        num = j['port']
        if num in input_ports:
            continue
        else:
            pkts_by_port[num].append(j)
    return pkts_by_port


def check_out_pkts(expected_pkt_lst, captured_pkt_lst, input_ports):
    ''' sniffs packet expected on output '''
    expected_pkts_by_port = packets_by_port(expected_pkt_lst, input_ports)
    captured_pkts_by_port = packets_by_port(captured_pkt_lst, input_ports)
    for port_num in expected_pkts_by_port:
        captured_lst = captured_pkts_by_port[port_num]
        expected_lst = expected_pkts_by_port[port_num]
        num_captured = len(captured_lst)
        num_expected = len(expected_lst)
        if num_captured < num_expected:
            range_len = num_captured
        else:
            range_len = num_expected
        for i in range(range_len):
            captured_pkt = byte_to_hex(str(captured_lst[i]['packet']))
            expected_pkt = byte_to_hex(str(expected_lst[i]['packet']))
            assert expected_lst[i]['port'] == captured_lst[i]['port']
            result = split_string(captured_pkt, expected_pkt)
            if result != "equal":
                return result
        if num_captured != num_expected:
            return ("FAILED: Expected %d packets on port %d, but the number of"
                    " packets captured on that port were %d"
                    "" % (num_expected, port_num, num_captured))
    return "All packets as expected"


# check_equality() is not currently used in this code, and pkt_str()
# is only called from check_equality().  Leave in for now in case
# there is something useful here for later.

def pkt_str(pack):
    '''gets value from packet in the form of str '''
    old_stdout = sys.stdout
    sys.stdout = mystdout = StringIO()
    pack.show2()
    sys.stdout = old_stdout
    return mystdout.getvalue()


def check_equality(p, exp_pkt1):
    ''' compares 2 packets - expected and packet which came '''
    if pkt_str(p['packet']) == pkt_str(exp_pkt1):
        return "equal"
    else:
        return "not equal"