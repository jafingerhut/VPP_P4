# VPP_P4
A subset of VPP implemented in P4

The project aims to implement the features of VPP in P4. Initially the program here implements only a certain set of basic features.
IPV4 unicast features
1. Drops the packets if the forwarding detail is not found among the table entries.
2. Checks for the ttl of the packet in the header, and drops received packets with ttl = 1 or 0. 
3. The P4 program is implemented such that it checks the table entries for MTU and drops the packets if the packet size is greater than the MTU. A number of test cases are checked for this, by constructing packets with Raw input appended.
4. A subset of IPv4 multicast forwarding, including packet replication to multiple output ports, and multicast RPF check.

Automated test cases are implemented in Python and have the functionality to send and receive packets on different port numbers.
The packets output by the P4 program, run using the `simple_switch` process from the p4lang/behavioral-model repository, are checked to verify that they contain the exact contents expected.  Any difference in number of packets, length of packets, or content of packet headers or payload bytes are detected and reported as a test failure.

Scapy is used to send and capture packets on the required virtual ethernet interfaces.

Simple switch is like a interface to connect to hardware. It obtains the json file and creates the necessary maps to execute the p4 program.

Steps to execute the test cases:

Change to the directory where path where the test Python program is
stored, here in VPP_P4 folder.  Then type the following commands:

```
# Only needed once after booting the system, to create veth interfaces:
# Get a copy of this repo: https://github.com/jafingerhut/p4-guide
sudo <p4-guide-root>/bin/veth_setup.sh

# Repeat compilation step whenever you change the P4 program source code
p4c-bm2-ss <P4_program_name>.p4 -o <P4_program_name>.p4

sudo <test_program>.py --json <P4_program_name>.json
```

For example:

```
p4c-bm2-ss demo1.p4_16.p4 -o demo1.p4_16.p4
sudo ./demo1_tests.py --json demo1.p4_16.json
```

where:

```
./demo1_tests.py - name of the test file
--json - option to specify the JSON file of the P4 program.
demo1.p4_16.json - json file name
```

This will run the `simple_switch` process, assign port numbers to veth interfaces and `simple_switch` remains running until the packets are received on the expcted ports.


# Older steps that should no longer be necessary with current code

If the above steps don't work, One can try with the following steps. 

1. Compile and execute the P4 program.

The P4 program is used from another git repository: https://github.com/jafingerhut/p4-guide. The P4 program updated to implement VPP's IPv4 unicast features is in the repository.
One needs to run the simple switch to assign ports to virtual ethernet addresses. 

Steps:
Open a new terminal

Traverse to the folder containing the p4 program you want to execute.
cd ~/p4/p4-guide/demo1

Execute the simple switch program now....
sudo simple_switch --log-console -i 0@veth2 -i 1@veth4 -i 2@veth6 -i 3@veth8 -i 4@veth10 -i 5@veth12 -i 6@veth14 -i 7@veth16 demo1.p4_16.json

Keep the simple switch running all the time as you implement the test cases.


2. Execute the .py file to send packets - test1

Open new terminal

Traverse to the folder containing the python test program.
cd ~/VPP_P4

To execute the .py file (run the program)
sudo ./demo1_tests.py

This program when executed will fill the tables with entries required to forward some packets as expected. Also it has commands to send the packet over the needed port number. 
'sudo' is used to run the test program with root permissions, needed because the Scapy library needs these permissions to send packets to, and capture packets from, Ethernet interfaces.

To see the packets being sent on particular veth interface, one can observe the tcp dump.
Enter the following commands on new terminals

Example: to check the packet flow on veth2
```
sudo tcpdump -e -n --number -v -i veth2
```

Example: to check the packet flow on veth6 
```
sudo tcpdump -e -n --number -v -i veth6
```


4. To check which processes are already running 
```
ps ax
```
This displays the processes still running along with their process IDs. 

To kill a process 
```
sudo kill PID
```
using sudo will force the process to terminate.
