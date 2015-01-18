//============================================================================
// Name        : wiretap.cpp
// Author      :
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================
#include "wiretap.h"

bool getBit(unsigned char byteValue, int pos) // position in range 0-7
		{
	return (byteValue >> pos) & 0x1;
}
void makeMacDestAddress(struct ethhdr* ether_header, char *macAddrToString) {
	char bufferForMacStore[3];
	//char macAddrToString[18] = "";
	for (int j = 0; j < 6; j++) {
		sprintf(bufferForMacStore, "%02x%s", ether_header->h_dest[j],
				(j == 5) ? "" : ":");
		strcat(macAddrToString, bufferForMacStore);
	}
}

void makeMacSourceAddress(struct ethhdr* ether_header, char *macAddrToString) {
	char bufferForMacStore[3];
	//char macAddrToString[18] = "";
	for (int j = 0; j < 6; j++) {
		sprintf(bufferForMacStore, "%02x%s", ether_header->h_source[j],
				(j == 5) ? "" : ":");
		strcat(macAddrToString, bufferForMacStore);
	}
}

void storeInMap(std::map<string, int> &mapName, string keyForMap) {
	it = mapName.find(keyForMap);
	if (it == mapName.end()) {
		mapName[keyForMap] = 1;

	} else {
		it->second++;
	}

}

void printMap(std::map<string, int> printMapToConsole) {
	if (printMapToConsole.empty()) {
		std::cout << "(No Results)" << endl;
		;
	} else {
		for (map<string, int>::const_iterator it = printMapToConsole.begin();
				it != printMapToConsole.end(); ++it) {
			std::cout << it->first << "\t" << it->second << "\n";
		}
	}
}
void updateTCPFlags(char flagsByte) {
	if (getBit(flagsByte, 5)) {
		it = TLayerTCPFlagCountMap.find("URG");
		it->second++;

	}
	if (getBit(flagsByte, 4)) {
		it = TLayerTCPFlagCountMap.find("ACK");
		it->second++;

	}
	if (getBit(flagsByte, 3)) {
		it = TLayerTCPFlagCountMap.find("PSH");
		it->second++;

	}
	if (getBit(flagsByte, 2)) {
		it = TLayerTCPFlagCountMap.find("RST");
		it->second++;

	}
	if (getBit(flagsByte, 1)) {
		it = TLayerTCPFlagCountMap.find("SYN");
		it->second++;

	}
	if (getBit(flagsByte, 0)) {
		it = TLayerTCPFlagCountMap.find("FIN");
		it->second++;

	}

}
void processTCPOptions(uint8_t* seekToOptions, tcphdr* tcp_header) {
	long int count = 0;
	long int NOPcount = 0;
	if (tcp_header->th_off * 4 > 20) {
		while (true) {
			tcp_option_info* currSeekToOptions = (tcp_option_info*) seekToOptions;
			if (currSeekToOptions->kind == 1 /* NOP */) {
				if (NOPcount < 1) {
					char buffer[50];
					sprintf(buffer, "%u (0x%02x)", currSeekToOptions->kind,
							currSeekToOptions->kind);
					storeInMap(OptionsMap, buffer);
					NOPcount++;
				}
				seekToOptions++;  
				count++;

			} else if (currSeekToOptions->kind != 1 /* Others */) {
				char buffer[50];
				sprintf(buffer, "%u (0x%02x)", currSeekToOptions->kind,
						currSeekToOptions->kind);
				storeInMap(OptionsMap, buffer);
				seekToOptions += currSeekToOptions->size;
				count += currSeekToOptions->size;
			}

			if (tcp_header->th_off * 4 - 20 == count /* end */) {
				break;
			}

		}
	}
}
void my_callback(u_char *packetinfo, const struct pcap_pkthdr* header,
		const u_char* packet) {
	// destination mac address to string
	struct ethhdr* ether_header = (struct ethhdr*) packet;

	char destaddrmac[18] = "";
	makeMacDestAddress(ether_header, destaddrmac);
	// src mac address to string
	char srcaddrmac[18] = "";
	makeMacSourceAddress(ether_header, srcaddrmac);

// logic for 1st packet
	if (countOFPackets == 0) {
		minSizeOfPacket = header->len;
		timeOfFirstPacket = header->ts.tv_sec;
		captureStartTime = localtime(&header->ts.tv_sec);
		strftime(timetmp, sizeof(timetmp), "%Y-%m-%d  %H:%M:%S %Z",
				captureStartTime);
		TLayerTCPFlagCountMap["URG"] = 0;
		TLayerTCPFlagCountMap["ACK"] = 0;
		TLayerTCPFlagCountMap["PSH"] = 0;
		TLayerTCPFlagCountMap["RST"] = 0;
		TLayerTCPFlagCountMap["SYN"] = 0;
		TLayerTCPFlagCountMap["FIN"] = 0;

	}

//Counting Packet No for Summary
	countOFPackets++;	
//average size of packets
	avgSizeOfPackets = avgSizeOfPackets + header->len;
	if (header->len > maxSizeOfPacket) {
		maxSizeOfPacket = header->len;
	}
	if (header->len < minSizeOfPacket) {
		minSizeOfPacket = header->len;
	}
	timeOfLastPacket = header->ts.tv_sec;

// store dest mac address n respective packets in map

	storeInMap(destAddrMap, destaddrmac);
	// store src mac address n respective packets in map

	storeInMap(srcAddrMap, srcaddrmac);
//Now in IP part network layer
	struct iphdr* ip_header = (struct iphdr*) (packet + ETHER_HDR_LEN);
	char src_ip[INET_ADDRSTRLEN];
	char dest_ip[INET_ADDRSTRLEN];
	// Ignore IPv6 Packets
	if (ip_header->version == 0x6) {
		storeInMap(protocountmap, "0x86DD");
		return;
	}
//Ether header IP then check source and dest ip
	if (ntohs(ether_header->h_proto) == ETHERTYPE_IP) {
		inet_ntop(AF_INET, &(ip_header->daddr), dest_ip, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(ip_header->saddr), src_ip, INET_ADDRSTRLEN);

		// store IP prtocols n respective packets in map
		storeInMap(protocountmap, "IP");
		// store dest ip address n respective packets in map
		storeInMap(destipmap, dest_ip);
		// store src ip address n respective packets in map
		storeInMap(srcipmap, src_ip);

		//Transport Layer Protocols
		if (ip_header->protocol == IPPROTO_TCP) {

			struct tcphdr* tcp_header = (struct tcphdr*) (packet + ETHER_HDR_LEN
					+ sizeof(iphdr));
//Source TCP ports
			char buffer[50];
			sprintf(buffer, "%u", ntohs(tcp_header->th_sport));
			storeInMap(TLayerTCPSPortCountMap, buffer);
//Destination TCP ports
			sprintf(buffer, "%u", ntohs(tcp_header->th_dport));
			storeInMap(TLayerTCPDPortCountMap, buffer);
//TCP FLags Check
			char* seekToFlags = (char*) (packet + ETHER_HDR_LEN + sizeof(iphdr)
					+ 13);
			char flagsByte;
			memcpy(&flagsByte, seekToFlags, 1);
			updateTCPFlags(flagsByte);
//TCP Options Processing

			uint8_t* seekToOptions = (uint8_t*) (packet + ETHER_HDR_LEN
					+ sizeof(iphdr) + sizeof(tcphdr));
			processTCPOptions(seekToOptions, tcp_header);

//TCP Count Proto Count
			storeInMap(TLayerProtoCountMap, "TCP");

		} else if (ip_header->protocol == IPPROTO_UDP) {

			struct udphdr* udp_header = (struct udphdr*) (packet + ETHER_HDR_LEN
					+ sizeof(iphdr));

			//Source UDP ports
			char buffer[50];
			sprintf(buffer, "%u", ntohs(udp_header->uh_sport));
			storeInMap(TLayerUDPSPortCountMap, buffer);
			//Destination UDP ports
			sprintf(buffer, "%u", ntohs(udp_header->uh_dport));
			storeInMap(TLayerUDPDPortCountMap, buffer);
// count UDP protocol packets
			storeInMap(TLayerProtoCountMap, "UDP");

		} else if (ip_header->protocol == IPPROTO_ICMP) {
			struct icmp* icmp_header = (struct icmp*) (packet + ETHER_HDR_LEN
					+ sizeof(iphdr));

//Processing ICMP Type
			char buffer[50];
			sprintf(buffer, "%u", icmp_header->icmp_type);
			storeInMap(TLayerICMPTypCountMap, buffer);

//Processing ICMP Code
			sprintf(buffer, "%u", icmp_header->icmp_code);
			storeInMap(TLayerICMPCodeCountMap, buffer);
//Counting ICMP

			storeInMap(TLayerProtoCountMap, "ICMP");

		} else {
//Counting ICMP
			char buffer[50];
			sprintf(buffer, "%u", ip_header->protocol);
			storeInMap(TLayerProtoCountMap, buffer);

		}

	} else if (ntohs(ether_header->h_proto) == ETHERTYPE_ARP) {
		// store ARP prtocols n respective packets in map
		storeInMap(protocountmap, "ARP");

		//Find Unique ARP participants
		struct arphddr* arp_header = (struct arphddr*) (packet + ETHER_HDR_LEN);
		// src mac address to string
		char arpMacToString[18] = "";
		makeMacSourceAddress(ether_header, arpMacToString);
		char arp_src_ip[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(arp_header->__ar_sip), arp_src_ip,
		INET_ADDRSTRLEN);
		char buffer[50];
		sprintf(buffer, "%s / %s", arpMacToString, arp_src_ip);
		storeInMap(uniqARPPartcountmap, buffer);

	} else if (ntohs(ether_header->h_proto) < 0x600) {
		// store less then IP prtocols n respective packets in map
		char buffer[50];
		sprintf(buffer, "%d (0x%02X)", ntohs(ether_header->h_proto),
				ntohs(ether_header->h_proto));
		storeInMap(protocountmap, buffer);
	}



}

int main(int argc, char * argv[]) {
	int packet_counter = 0;
	pcap_t *handle; /* Session handle */
	char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
	const u_char *packet; /* The actual packet */

	if (argc == 1) {
		cout << "Mention File Name" << endl; //Core Dumped if file name not included
		cout
				<< "\n--help. Example: ./wiretap --help.\n--open <capture file to open>. Example: “./wiretap --open capture.pcap"
				<< endl;
		exit(1);
	}
	for (int i = 1; i < argc; i++) {
		if (strcmp("--help", argv[i]) == 0) {
			cout
					<< "\n--help. Example: ./wiretap --help.\n--open <capture file to open>. Example: “./wiretap --open capture.pcap"
					<< endl;
		} else if (strcmp("--open", argv[i]) == 0) {
			handle = pcap_open_offline(argv[i + 1], errbuf); //Opening pcap File
			if (handle == NULL) {
				cout << "INVALID FILE: Check PCAP File Name" << endl;
				exit(1);
			}
		} else if (argc == 2) {
			cout
					<< "\n--help. Example: ./wiretap --help.\n--open <capture file to open>. Example: “./wiretap --open capture.pcap"
					<< endl;
			exit(1);
		}

	}
	if (pcap_datalink(handle) != DLT_EN10MB) { //Checking if header is of ethernet
		cout << "Data provided has not been captured from Ethernet" << endl;
		exit(1);
	}
	/* Grab a packet */
	int loopstatus = pcap_loop(handle, 0, my_callback, NULL);
	if (loopstatus == -1) {
		cout << "pcap_loop error occured" << endl;
	} else if (loopstatus == -2) {
		cout
				<< "loop  terminated  due  to  a  call  to pcap_breakloop() before any packets were processed"
				<< endl;
	}

// print summary;
	cout
			<< "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
			<< endl;
	cout << "=========Packet capture summary=========" << endl;
	cout << "Capture start date: " << timetmp << endl;
	cout << "Capture duration: " << timeOfLastPacket - timeOfFirstPacket
		<< "  " <<"seconds"<< endl;
	cout << "Packets in capture: " << countOFPackets << endl;
	cout << "Maximum Packet Size : " << maxSizeOfPacket << endl;
	cout << "Minimum Packet Size : " << minSizeOfPacket << endl;
	cout << "Average Size Of Packet : "
			<< (double) avgSizeOfPackets / countOFPackets << endl;
	cout << "=========Link layer=========" << endl;
	cout << "---------Source ethernet addresses---------" << endl;
	printMap(srcAddrMap);
	cout << "---------Destination ethernet addresses---------" << endl;
	printMap(destAddrMap);
	cout << "=========Network layer=========" << endl;
	cout << "---------Network layer protocols---------" << endl;
	printMap(protocountmap);
	cout << "---------Source IP addresses---------" << endl;
	printMap(srcipmap);
	cout << "---------Destination IP addresses---------" << endl;
	printMap(destipmap);
	cout << "---------Unique ARP participants---------" << endl;
	printMap(uniqARPPartcountmap);
	cout << "=========Transport layer=========" << endl;

	cout << "---------Transport layer protocols---------" << endl;
	printMap(TLayerProtoCountMap);
	cout << "=========Transport layer: TCP=========" << endl;

	cout << "---------Source TCP ports---------" << endl;
	printMap(TLayerTCPSPortCountMap);
	cout << "---------Destination TCP ports---------" << endl;
	printMap(TLayerTCPDPortCountMap);
	cout << "---------TCP flags---------" << endl;
	printMap(TLayerTCPFlagCountMap);
	cout << "---------TCP options---------" << endl;
	printMap(OptionsMap);
	cout << "=========Transport layer: UDP=========" << endl;

	cout << "---------Source UDP ports---------" << endl;
	printMap(TLayerUDPSPortCountMap);
	cout << "---------Destination UDP ports---------" << endl;
	printMap(TLayerUDPDPortCountMap);
	cout << "=========Transport layer: ICMP=========" << endl;

	cout << "---------ICMP types---------" << endl;
	printMap(TLayerICMPTypCountMap);
	cout << "---------ICMP codes---------" << endl;

	printMap(TLayerICMPCodeCountMap);
	cout
			<< "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
			<< endl;

	/* And close the session */
	pcap_close(handle);

	return 0;
}
