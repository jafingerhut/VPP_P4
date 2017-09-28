/* -*- mode: P4_14 -*- */
/*
Copyright 2017 Cisco Systems, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

header_type tcp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset : 4;
        res : 4;
        flags : 8;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}

header_type fwd_metadata_t {
    fields {
        l2ptr     : 32;
        out_bd    : 24;
    }
}

header_type debug_metadata_t {
    fields {
        stack_valid_vector : 4;
        fld1 : 4;
        fld2 : 4;
    }
}

header ethernet_t ethernet;
#define IPV4_DEPTH 4
header ipv4_t ipv4[IPV4_DEPTH];
header tcp_t tcp;
metadata fwd_metadata_t fwd_metadata;
metadata debug_metadata_t debug_metadata;

parser start {
    return parse_ethernet;
}

#define ETHERTYPE_IPV4 0x0800

#define IP_PROTOCOLS_IPV4              4
#define IP_PROTOCOLS_TCP               6

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
    }
}

parser parse_ipv4 {
    extract(ipv4[next]);
    return select(latest.protocol) {
        IP_PROTOCOLS_IPV4: parse_ipv4;
        IP_PROTOCOLS_TCP: parse_tcp;
        default: ingress;
    }
}

parser parse_tcp {
    extract(tcp);
    return ingress;
}

// Why bother creating an action that just does one primitive action?
// That is, why not just use 'drop' as one of the possible actions
// when defining a table?  Because the P4_14 compiler does not allow
// primitive actions to be used directly as actions of tables.  You
// must use 'compound actions', i.e. ones explicitly defined with the
// 'action' keyword like below.

action my_nop() {
}

action set_debug_fld1() {
    modify_field(debug_metadata.fld1, debug_metadata.stack_valid_vector);
    bit_and(ethernet.srcAddr, ethernet.srcAddr, 0xffffffffff00);
    bit_or(ethernet.srcAddr, ethernet.srcAddr, debug_metadata.stack_valid_vector);
}

table debug_ipv4_hdr_stack1 {
    reads {
        debug_metadata.stack_valid_vector : exact;
    }
    actions {
        set_debug_fld1;
    }
}

action set_debug_fld2() {
    modify_field(debug_metadata.fld2, debug_metadata.stack_valid_vector);
    bit_and(ethernet.dstAddr, ethernet.dstAddr, 0xffffffffff00);
    bit_or(ethernet.dstAddr, ethernet.dstAddr, debug_metadata.stack_valid_vector);
}

table debug_ipv4_hdr_stack2 {
    reads {
        debug_metadata.stack_valid_vector : exact;
    }
    actions {
        set_debug_fld2;
    }
}

action add_hdr0() {
    add_header(ipv4[0]);
    // These fields are not necessarily completely correct in an
    // output packet, but this is just a program for testing P4 header
    // stack operations, not a full tunneling implementation.
    modify_field(ipv4[0].version, 4);
    modify_field(ipv4[0].ihl, 5);
    modify_field(ipv4[0].diffserv, 0);
    modify_field(ipv4[0].totalLen, 20);
    modify_field(ipv4[0].identification, 0);
    modify_field(ipv4[0].flags, 0);
    modify_field(ipv4[0].fragOffset, 0);
    modify_field(ipv4[0].ttl, 64 + 0);
    modify_field(ipv4[0].protocol, IP_PROTOCOLS_IPV4);
    modify_field(ipv4[0].hdrChecksum, 0);
    modify_field(ipv4[0].srcAddr, 0xface0000 | 0);
    modify_field(ipv4[0].dstAddr, 0);
}

action add_hdr1() {
    add_header(ipv4[1]);
    modify_field(ipv4[1].version, 4);
    modify_field(ipv4[1].ihl, 5);
    modify_field(ipv4[1].diffserv, 0);
    modify_field(ipv4[1].totalLen, 20);
    modify_field(ipv4[1].identification, 0);
    modify_field(ipv4[1].flags, 0);
    modify_field(ipv4[1].fragOffset, 0);
    modify_field(ipv4[1].ttl, 64 + 1);
    modify_field(ipv4[1].protocol, IP_PROTOCOLS_IPV4);
    modify_field(ipv4[1].hdrChecksum, 0);
    modify_field(ipv4[1].srcAddr, 0xface0000 | 1);
    modify_field(ipv4[1].dstAddr, 0);
}

action add_hdr2() {
    add_header(ipv4[2]);
    modify_field(ipv4[2].version, 4);
    modify_field(ipv4[2].ihl, 5);
    modify_field(ipv4[2].diffserv, 0);
    modify_field(ipv4[2].totalLen, 20);
    modify_field(ipv4[2].identification, 0);
    modify_field(ipv4[2].flags, 0);
    modify_field(ipv4[2].fragOffset, 0);
    modify_field(ipv4[2].ttl, 64 + 2);
    modify_field(ipv4[2].protocol, IP_PROTOCOLS_IPV4);
    modify_field(ipv4[2].hdrChecksum, 0);
    modify_field(ipv4[2].srcAddr, 0xface0000 | 2);
    modify_field(ipv4[2].dstAddr, 0);
}

action add_hdr3() {
    add_header(ipv4[3]);
    modify_field(ipv4[3].version, 4);
    modify_field(ipv4[3].ihl, 5);
    modify_field(ipv4[3].diffserv, 0);
    modify_field(ipv4[3].totalLen, 20);
    modify_field(ipv4[3].identification, 0);
    modify_field(ipv4[3].flags, 0);
    modify_field(ipv4[3].fragOffset, 0);
    modify_field(ipv4[3].ttl, 64 + 3);
    modify_field(ipv4[3].protocol, IP_PROTOCOLS_IPV4);
    modify_field(ipv4[3].hdrChecksum, 0);
    modify_field(ipv4[3].srcAddr, 0xface0000 | 3);
    modify_field(ipv4[3].dstAddr, 0);
}

action rm_hdr0() {
    remove_header(ipv4[0]);
}

action rm_hdr1() {
    remove_header(ipv4[1]);
}

action rm_hdr2() {
    remove_header(ipv4[2]);
}

action rm_hdr3() {
    remove_header(ipv4[3]);
}

table ipv4_da_lpm {
    reads {
        ipv4[0].dstAddr       : lpm;
    }
    actions {
        add_hdr0;
        add_hdr1;
        add_hdr2;
        add_hdr3;
        rm_hdr0;
        rm_hdr1;
        rm_hdr2;
        rm_hdr3;
        my_nop;
    }
}

action set_egress_spec_1() {
    modify_field(standard_metadata.egress_spec, 1);
}

table set_output_port {
    actions {
        set_egress_spec_1;
    }
}

action clear_stack_valid_vector_action() {
    modify_field(debug_metadata.stack_valid_vector, 0);
}
table clear_stack_valid_vector1 {
    actions { clear_stack_valid_vector_action; }
}
table clear_stack_valid_vector2 {
    actions { clear_stack_valid_vector_action; }
}

action set_bit_0_of_stack_valid_vector_action() {
    bit_or(debug_metadata.stack_valid_vector, debug_metadata.stack_valid_vector, 1 << 0);
}
table set_bit_0_of_stack_valid_vector1 {
    actions { set_bit_0_of_stack_valid_vector_action; }
}
table set_bit_0_of_stack_valid_vector2 {
    actions { set_bit_0_of_stack_valid_vector_action; }
}

action set_bit_1_of_stack_valid_vector_action() {
    bit_or(debug_metadata.stack_valid_vector, debug_metadata.stack_valid_vector, 1 << 1);
}
table set_bit_1_of_stack_valid_vector1 {
    actions { set_bit_1_of_stack_valid_vector_action; }
}
table set_bit_1_of_stack_valid_vector2 {
    actions { set_bit_1_of_stack_valid_vector_action; }
}

action set_bit_2_of_stack_valid_vector_action() {
    bit_or(debug_metadata.stack_valid_vector, debug_metadata.stack_valid_vector, 1 << 2);
}
table set_bit_2_of_stack_valid_vector1 {
    actions { set_bit_2_of_stack_valid_vector_action; }
}
table set_bit_2_of_stack_valid_vector2 {
    actions { set_bit_2_of_stack_valid_vector_action; }
}

action set_bit_3_of_stack_valid_vector_action() {
    bit_or(debug_metadata.stack_valid_vector, debug_metadata.stack_valid_vector, 1 << 3);
}
table set_bit_3_of_stack_valid_vector1 {
    actions { set_bit_3_of_stack_valid_vector_action; }
}
table set_bit_3_of_stack_valid_vector2 {
    actions { set_bit_3_of_stack_valid_vector_action; }
}

control calc_stack_valid_vector1 {
    apply(clear_stack_valid_vector1);
    if (valid(ipv4[0])) {
        apply(set_bit_0_of_stack_valid_vector1);
    }
    if (valid(ipv4[1])) {
        apply(set_bit_1_of_stack_valid_vector1);
    }
    if (valid(ipv4[2])) {
        apply(set_bit_2_of_stack_valid_vector1);
    }
    if (valid(ipv4[3])) {
        apply(set_bit_3_of_stack_valid_vector1);
    }
}

control calc_stack_valid_vector2 {
    apply(clear_stack_valid_vector2);
    if (valid(ipv4[0])) {
        apply(set_bit_0_of_stack_valid_vector2);
    }
    if (valid(ipv4[1])) {
        apply(set_bit_1_of_stack_valid_vector2);
    }
    if (valid(ipv4[2])) {
        apply(set_bit_2_of_stack_valid_vector2);
    }
    if (valid(ipv4[3])) {
        apply(set_bit_3_of_stack_valid_vector2);
    }
}

control ingress {
    calc_stack_valid_vector1();
    apply(debug_ipv4_hdr_stack1);
    apply(set_output_port);
    apply(ipv4_da_lpm);
    calc_stack_valid_vector2();
    apply(debug_ipv4_hdr_stack2);
}

control egress {
}
