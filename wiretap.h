/*
 * wiretap.h
 *
 *  Created on: Oct 31, 2014
 *      Author: vivek
 */

#ifndef WIRETAP_H_
#define WIRETAP_H_

#include <iostream>
#include <stdlib.h>
#include </usr/include/netinet/ether.h>
#include </usr/include/netinet/ip.h>
#include </usr/include/netinet/ip6.h>
//#include </usr/include/netinet/tcp.h>
//#include </usr/include/netinet/udp.h>
#include </usr/include/netinet/ip_icmp.h>
#include </usr/include/net/if_arp.h>
#include </usr/include/arpa/inet.h>
#include </usr/include/linux/if_ether.h>
#include </usr/include/pcap/bpf.h>
#include </usr/include/pcap/pcap.h>
#include <time.h>
#include <map>
#include <string.h>

using namespace std;

struct udphdr {
	__extension__
	union {
		struct {
			u_int16_t uh_sport; /* source port */
			u_int16_t uh_dport; /* destination port */
			u_int16_t uh_ulen; /* udp length */
			u_int16_t uh_sum; /* udp checksum */
		};
		struct {
			u_int16_t source;
			u_int16_t dest;
			u_int16_t len;
			u_int16_t check;
		};
	};
};

typedef u_int32_t tcp_seq;

struct tcphdr {
	__extension__
	union {
		struct {
			u_int16_t th_sport; /* source port */
			u_int16_t th_dport; /* destination port */
			tcp_seq th_seq; /* sequence number */
			tcp_seq th_ack; /* acknowledgement number */
# if __BYTE_ORDER == __LITTLE_ENDIAN
			u_int8_t th_x2 :4; /* (unused) */
			u_int8_t th_off :4; /* data offset */
# endif
# if __BYTE_ORDER == __BIG_ENDIAN
			u_int8_t th_off:4; /* data offset */
			u_int8_t th_x2:4; /* (unused) */
# endif
			u_int8_t th_flags;
# define TH_FIN	0x01
# define TH_SYN	0x02
# define TH_RST	0x04
# define TH_PUSH	0x08
# define TH_ACK	0x10
# define TH_URG	0x20
			u_int16_t th_win; /* window */
			u_int16_t th_sum; /* checksum */
			u_int16_t th_urp; /* urgent pointer */
		};
		struct {
			u_int16_t source;
			u_int16_t dest;
			u_int32_t seq;
			u_int32_t ack_seq;
# if __BYTE_ORDER == __LITTLE_ENDIAN
			u_int16_t res1 :4;
			u_int16_t doff :4;
			u_int16_t fin :1;
			u_int16_t syn :1;
			u_int16_t rst :1;
			u_int16_t psh :1;
			u_int16_t ack :1;
			u_int16_t urg :1;
			u_int16_t res2 :2;
# elif __BYTE_ORDER == __BIG_ENDIAN
			u_int16_t doff:4;
			u_int16_t res1:4;
			u_int16_t res2:2;
			u_int16_t urg:1;
			u_int16_t ack:1;
			u_int16_t psh:1;
			u_int16_t rst:1;
			u_int16_t syn:1;
			u_int16_t fin:1;
# else
#  error "Adjust your <bits/endian.h> defines"
# endif
			u_int16_t window;
			u_int16_t check;
			u_int16_t urg_ptr;
		};
	};
};
struct arphddr {
	unsigned short int ar_hrd; /* Format of hardware address.  */
	unsigned short int ar_pro; /* Format of protocol address.  */
	unsigned char ar_hln; /* Length of hardware address.  */
	unsigned char ar_pln; /* Length of protocol address.  */
	unsigned short int ar_op; /* ARP opcode (command).  */
	/* Ethernet looks like this : This bit is variable sized
	 however...  */
	unsigned char __ar_sha[ETH_ALEN]; /* Sender hardware address.  */
	unsigned char __ar_sip[4]; /* Sender IP address.  */
	unsigned char __ar_tha[ETH_ALEN]; /* Target hardware address.  */
	unsigned char __ar_tip[4]; /* Target IP address.  */

};
struct tcp_option_info {
	uint8_t kind;
	uint8_t size;
};

int countOFPackets = 0;
struct tm* captureStartTime;
char timetmp[29];
long int timeOfFirstPacket, timeOfLastPacket;
unsigned int maxSizeOfPacket = 0;
unsigned int minSizeOfPacket;
unsigned int avgSizeOfPackets = 0;
std::map<std::string, int>::iterator it;
std::map<std::string, int> destAddrMap;
std::map<std::string, int> srcAddrMap;
std::map<std::string, int> destipmap;
std::map<std::string, int> srcipmap;
std::map<std::string, int> protocountmap;
std::map<std::string, int> uniqARPPartcountmap;
std::map<std::string, int> TLayerProtoCountMap;
std::map<std::string, int> TLayerTCPSPortCountMap;
std::map<std::string, int> TLayerTCPDPortCountMap;
std::map<std::string, int> TLayerTCPFlagCountMap;
std::map<std::string, int> TLayerUDPSPortCountMap;
std::map<std::string, int> TLayerUDPDPortCountMap;
std::map<std::string, int> TLayerICMPTypCountMap;
std::map<std::string, int> TLayerICMPCodeCountMap;
std::map<std::string, int> OptionsMap;

#endif /* WIRETAP_H_ */
