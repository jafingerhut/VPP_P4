#! /bin/bash

BASENAME="ipv4-hdr-stack"
#BASENAME="ipv4-hdr-stack2"
#BASENAME="ipv4-hdr-stack3"

P4_14_SRC="${BASENAME}.p4_14.p4"
P4_14_JSON="${BASENAME}.p4_14.json"
P4_16_SRC="${BASENAME}.p4_16.p4"
P4_16_JSON="${BASENAME}.p4_16.json"

set -x

# Compile P4_14 source to bmv2 JSON
p4c-bm2-ss --p4v 14 "${P4_14_SRC}" -o "${P4_14_JSON}"

# Translate P4_14 source to P4_16 source
p4test --p4v 14 --pp "${P4_16_SRC}" "${P4_14_SRC}"

# Compile translated P4_16 source to bmv2 JSON
p4c-bm2-ss "${P4_16_SRC}" -o "${P4_16_JSON}"
