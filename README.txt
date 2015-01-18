Project 3: Wiretap
-----------------------

Name: Vivek Supe		
uname: vsupe

Name: Jay Modi	
uname: jmmodi

------------------------

This is a partial emulation of packet analysis tool like tcpdump or wireshark which analyze intercepted packets being transmitted or received over a LAN. One prominent use of this information is in troubleshooting network configuration and reachability. We use functions like pcap_open_offline(), pcap_datalink(), pcap_loop(), pcap_loop() and pcap_close() to implement this packet parser.

Files Includes With This Project:
	wiretap.cpp		wiretap.h

Tasks Accomplished:
	+ PCAP file Summary
	+ Processing TCP Flags
	+ Processing TCP Options
	+ Successful Implementation of pcap_loop().

Guide:

1 - Type WIN:"echo %cd%: or for LINUX:"pwd" so check current directory. Now we use "cd" to change directory to the folder which has the Makefile & C File.
2 - We compile the file. To do so we have to get into current directory where the code is based and type "$make" command.
3 - Once the code has compiled we can go ahead with running the program. So do so we first understand the flags used.
        	 ./wiretap [option1, ..., optionN]
		• --help. Example: “./wiretap --help”.
		• --open <capture file to open>. Example: “./wiretap --open capture.pcap”.

Some valid commands are:
	•./wiretap --help
	This will print help on console.
	•./wiretap --open <FILENAME>
	This will process the pcap file.
	•./wiretap --help --open <FILENAME>
	•./wiretap --open <FILENAME> --help
	This will process the pcap file and also print the help on standard out.

Understanding Outputs:
	1- $./wiretap --help --open wget.pcap 

		--help. Example: ./wiretap --help.
		--open <capture file to open>. Example: “./wiretap --open capture.pcap
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		=========Packet capture summary=========
		Capture start date: 2009-09-14  12:39:57 EDT
		Capture duration: 11
		Packets in capture: 328
		Maximum Packet Size : 1514
		Minimum Packet Size : 42
		Average Size Of Packet : 586.47
		=========Link layer=========
		---------Source ethernet addresses---------
		00:0f:1f:71:a4:4e	137
		00:0f:1f:73:d6:0b	1
		00:13:72:54:78:2f	10
		00:22:19:30:c6:1b	2
		00:d0:05:56:a8:00	79
		01:80:c2:00:00:00	6
		09:00:09:00:00:67	5
		ff:ff:ff:ff:ff:ff	88
		---------Destination ethernet addresses---------
		00:0f:1f:71:a4:4e	137
		00:0f:1f:73:d6:0b	1
		00:13:72:54:78:2f	10
		00:22:19:30:c6:1b	2
		00:d0:05:56:a8:00	79
		01:80:c2:00:00:00	6
		09:00:09:00:00:67	5
		ff:ff:ff:ff:ff:ff	88
		=========Network layer=========
		---------Network layer protocols---------
		38 (0x26)	6
		82 (0x52)	1
		98 (0x62)	4
		ARP	83
		IP	234
		---------Source IP addresses---------
		129.79.245.225	1
		129.79.245.233	1
		129.79.246.17	1
		129.79.246.18	4
		129.79.246.196	88
		129.79.246.247	1
		129.79.246.27	2
		129.79.247.6	9
		157.166.224.25	73
		66.225.202.210	3
		75.102.3.15	51
		---------Destination IP addresses---------
		129.79.245.106	2
		129.79.246.196	136
		129.79.246.236	1
		129.79.247.255	6
		129.79.247.6	9
		157.166.224.25	34
		255.255.255.255	1
		66.225.202.210	6
		75.102.3.15	39
		---------Unique ARP participants---------
		00:0f:1f:71:a4:4e / 129.79.247.6	1
		00:13:72:54:78:2f / 129.79.246.196	1
		ff:ff:ff:ff:ff:ff / 129.79.245.148	1
		ff:ff:ff:ff:ff:ff / 129.79.245.182	1
		ff:ff:ff:ff:ff:ff / 129.79.245.193	3
		ff:ff:ff:ff:ff:ff / 129.79.245.211	1
		ff:ff:ff:ff:ff:ff / 129.79.245.223	1
		ff:ff:ff:ff:ff:ff / 129.79.245.239	1
		ff:ff:ff:ff:ff:ff / 129.79.245.248	1
		ff:ff:ff:ff:ff:ff / 129.79.245.252	2
		ff:ff:ff:ff:ff:ff / 129.79.245.38	4
		ff:ff:ff:ff:ff:ff / 129.79.245.86	4
		ff:ff:ff:ff:ff:ff / 129.79.246.203	1
		ff:ff:ff:ff:ff:ff / 129.79.246.27	26
		ff:ff:ff:ff:ff:ff / 129.79.246.39	1
		ff:ff:ff:ff:ff:ff / 129.79.247.10	1
		ff:ff:ff:ff:ff:ff / 129.79.247.105	1
		ff:ff:ff:ff:ff:ff / 129.79.247.191	1
		ff:ff:ff:ff:ff:ff / 129.79.247.254	2
		ff:ff:ff:ff:ff:ff / 129.79.247.6	29
		=========Transport layer=========
		---------Transport layer protocols---------
		TCP	208
		UDP	26
		=========Transport layer: TCP=========
		---------Source TCP ports---------
		17847	6
		27940	39
		6077	34
		65256	2
		80	127
		---------Destination TCP ports---------
		17847	3
		2003	2
		27940	51
		6077	73
		80	79
		---------TCP flags---------
		ACK	203
		FIN	6
		PSH	16
		RST	1
		SYN	7
		URG	0
		---------TCP options---------
		1 (0x01)	206
		2 (0x02)	7
		3 (0x03)	6
		4 (0x04)	7
		8 (0x08)	207
		=========Transport layer: UDP=========
		---------Source UDP ports---------
		138	1
		15883	1
		162	1
		1876	1
		20628	1
		22347	1
		25520	1
		26330	1
		26600	1
		28598	1
		3152	1
		4767	1
		53	9
		54362	1
		60385	1
		60386	1
		60387	1
		60388	1
		---------Destination UDP ports---------
		137	5
		138	1
		15883	1
		162	1
		1876	1
		20628	1
		22347	1
		25520	1
		26330	1
		26600	1
		28598	1
		4767	1
		53	9
		712	1
		=========Transport layer: ICMP=========
		---------ICMP types---------
		(No Results)
		---------ICMP codes---------
		(No Results)
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


	2- $./wiretap --open IPv6_1_packet.pcap 
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
		=========Packet capture summary=========
		Capture start date: 1999-03-11  08:45:02 EST
		Capture duration: 0
		Packets in capture: 0
		Maximum Packet Size : 90
		Minimum Packet Size : 90
		Average Size Of Packet : inf
		=========Link layer=========
		---------Source ethernet addresses---------
		00:60:97:07:69:ea	1
		---------Destination ethernet addresses---------
		00:60:97:07:69:ea	1
		=========Network layer=========
		---------Network layer protocols---------
		0x86DD	1
		---------Source IP addresses---------
		(No Results)
		---------Destination IP addresses---------
		(No Results)
		---------Unique ARP participants---------
		(No Results)
		=========Transport layer=========
		---------Transport layer protocols---------
		(No Results)
		=========Transport layer: TCP=========
		---------Source TCP ports---------
		(No Results)
		---------Destination TCP ports---------
		(No Results)
		---------TCP flags---------
		ACK	0
		FIN	0
		PSH	0
		RST	0
		SYN	0
		URG	0
		---------TCP options---------
		(No Results)
		=========Transport layer: UDP=========
		---------Source UDP ports---------
		(No Results)
		---------Destination UDP ports---------
		(No Results)
		=========Transport layer: ICMP=========
		---------ICMP types---------
		(No Results)
		---------ICMP codes---------
		(No Results)
		~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

