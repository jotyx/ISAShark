/*
 * Author: Adam S.
 * 2017
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <iostream>
#include <vector>

#include <pcap.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>

#define SIZE_ETHERNET (14)
#define SIZE_VLAN (18)
#define SIZE_VLANad (22)
#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_VLANad 0x88A8
#define MAX_PACKET_SIZE 65535

using namespace std;

string aggrKey;
string sortKey;
string limit;
string filter;
string *files;
int numberOfFiles = 0;
int numberOfPackets = 0;
const u_char *packet;

struct packetRecord {
	int number;
	long ts;

	unsigned int size = 0;
	int ip_off = 0;
	unsigned short ip_len;
	short ip_hl;
	int data;
	char mf;
	int id;

	string aggr;
	int packets;

	string srcmac;
	string dstmac;

	string ip;
	string srcip;
	string dstip;
	int ttl_hl;

	string protocol;
	int srcport; 
	int dstport; 

	unsigned int seq;
	unsigned int ackN;

	bool cwr;
	bool ece;
	bool urg;
	bool ack;
	bool psh;
	bool rst;
	bool syn;
	bool fin;

	int vlanid1 = -1;
	int vlanid2 = -1;

	vector<unsigned char> ip4data;
	bool frag = false;
	bool complete = false;
};

void errExit(string err, int code);
void printHelp();
void processArgs(int argc, char *argv[]);
void processPacket(packetRecord *record, int ip_type, string net_type);
void sortPackets(packetRecord * packetArray);
void printFinal(packetRecord * packetArray);
string printICMP(int type, int code, int version);
bool fragmentMatch(packetRecord fragment1, packetRecord fragment2);
void connectFragments(packetRecord * packetArray);
packetRecord * aggrPackets(packetRecord * packetArray);
void ipv4L4(packetRecord * record);

int main(int argc, char *argv[]) {
	processArgs(argc, argv);

	int m = 0;
	char errbuf[256];
	struct pcap_pkthdr header;
	pcap_t *handle;

	for (int i = 0; i < numberOfFiles; i++) {
		if ((handle = pcap_open_offline(files[i].c_str(), errbuf)) == NULL)
			errExit("Can't open file.", 1);
		while ((packet = pcap_next(handle, &header)) != NULL)
			numberOfPackets++;
	}
	pcap_close(handle);

	packetRecord * packetArray = new packetRecord[numberOfPackets+1];

	for (int i = 0; i < numberOfFiles; i++) {
		if ((handle = pcap_open_offline(files[i].c_str(), errbuf)) == NULL)
			errExit("Can't open file.", 1);

		if (!filter.empty()) {
			struct bpf_program fp;
		 	if (pcap_compile(handle, &fp, filter.c_str(), 0, 0) == -1)
			  	errExit("pcap_compile() failed", 1);
			if (pcap_setfilter(handle, &fp) == -1)
			 	errExit("pcap_setfilter() failed", 1);
		}

		while ((packet = pcap_next(handle, &header)) != NULL) {

			packetArray[m].ts = (long)header.ts.tv_sec * (long)1000000 + (long)header.ts.tv_usec;
			packetArray[m].size = header.len;

			// Ethernet dest, and source MAC
			struct ether_header *eptr;
			eptr = (struct ether_header *) packet;

			// Internet protocol version
			int type;

			if (packet[12] == 129 && packet[13] == 0 )
				(packet[16] == 8 && packet[17] == 0 ) ? type = 4 : type = 6; // VLAN
			else if((packet[12] == 136) && (packet[13] == 168 ))
				(packet[20] == 8 && packet[21] == 0 ) ? type = 4 : type = 6; // VLANad
			else {
				(packet[12] == 8 && packet[13] == 0 ) ? type = 4 : type = 6; // ETHER
			}

			switch (ntohs(eptr->ether_type)) {
				case ETHERTYPE_IP: // ETHERNET IPv4 ***************
					processPacket(&packetArray[m], type, "ETHER");
					break;
				case ETHERTYPE_IPV6:  // ETHERNET IPv6 ************
					processPacket(&packetArray[m], type, "ETHER");
					break;
				case ETHERTYPE_VLAN:  // ETHERNET VLAN ************
					processPacket(&packetArray[m], type, "VLAN");
					break;
				case ETHERTYPE_VLANad: // ETHERNET VLANad *********
					processPacket(&packetArray[m], type, "VLANad");
					break;
				default:
					packetArray[m].protocol = "UNKNOWN";
					break;
			}
			m++;
		}
	}

	connectFragments(packetArray);
	if (!aggrKey.empty())
		packetArray = aggrPackets(packetArray);

	sortPackets(packetArray);
	printFinal(packetArray);

	delete [] files;
	delete [] packetArray;
	pcap_close(handle);
	return 0;
}

void connectFragments(packetRecord * packetArray) {
	for (int i = 0; i < numberOfPackets; i++) {
		if (packetArray[i].frag && !packetArray[i].complete) {
			unsigned char buffer[MAX_PACKET_SIZE];
			bool holes[MAX_PACKET_SIZE];
			for (int n = 0; n < MAX_PACKET_SIZE; n++)
				holes[n] = true;

			int index = 0;
			for (int n = packetArray[i].ip_off; n < (packetArray[i].data + packetArray[i].ip_off); n++) {
				buffer[n] = packetArray[i].ip4data[index];
				holes[n] = false;
				index++;
			}

			for (int j = 0; j < numberOfPackets; j++) {
				if (fragmentMatch(packetArray[i], packetArray[j]) &&  i != j &&
				packetArray[j].frag && !packetArray[j].complete) {
					packetArray[j].complete = true;

					int index = 0;
					for (int n = packetArray[j].ip_off; n < (packetArray[j].data + packetArray[j].ip_off); n++) {
						buffer[n] = packetArray[j].ip4data[index];
						holes[n] = false;
						index++;
					}

					if (packetArray[j].mf == 0) {
						packetArray[i].data = packetArray[j].ip_off + packetArray[j].data;
						packetArray[i].mf = 2;
					}
					if (packetArray[i].mf == 2) {
						for (int n = 0; n < MAX_PACKET_SIZE; n++) {
							if (holes[n] || n + 1 == MAX_PACKET_SIZE) {
								if (packetArray[i].data == n) {
									vector<unsigned char> tempV(buffer, buffer + n);

									packetArray[i] = packetArray[j];
									packetArray[i].ip4data = tempV;
									
									packetArray[i].complete = true;
									packetArray[i].frag = false;
									packetArray[i].number = j;
								}
								break;
							}
						}
						if (packetArray[i].complete)
							break;
					}
				}
			}
		}
		else if (!packetArray[i].frag) {
			packetArray[i].complete = true;
			packetArray[i].number = i;
		}
	}

	packetRecord empty;
	for (int i = 0; i < numberOfPackets; i++) {
		if (!packetArray[i].frag && packetArray[i].complete) {
			if (packetArray[i].ip4data.size() > 0)
				ipv4L4(&packetArray[i]);
		}
		else packetArray[i] = empty;
	}
	for (int i = 0; i < numberOfPackets; i++) {
		for (int j = 0; j < numberOfPackets-i; j++) {
			if (packetArray[j].number > packetArray[j+1].number) {
				packetArray[numberOfPackets] = packetArray[j];
				packetArray[j] = packetArray[j+1];
				packetArray[j+1] = packetArray[numberOfPackets];
			}
		}
	}
	int number = 1;
	for (int i = 0; i < numberOfPackets; i++) {
		if (!packetArray[i].protocol.empty()) {
			packetArray[i].number = number;
			number++;
		}
	}
}

void printFinal(packetRecord * packetArray) {
	if (aggrKey.empty()) {
		for (int i = 0; i < numberOfPackets; i++) {
			if (!packetArray[i].protocol.empty() && !packetArray[i].frag) {
				if (!limit.empty())
					if((i+1) > stoi(limit))
						break;

				if (packetArray[i].protocol.compare("UNKNOWN") == 0) {
					string temp = "Unknown protocol with packet number " + to_string(packetArray[i].number);
					errExit(temp.c_str(), 0);
					continue;
				}

				printf("%d: %lu %d | ", packetArray[i].number, packetArray[i].ts, packetArray[i].size);
				printf("Ethernet: %s %s ", packetArray[i].srcmac.c_str(), packetArray[i].dstmac.c_str());

				if (packetArray[i].vlanid1 >= 0)
					printf("%d ", packetArray[i].vlanid1);
				if (packetArray[i].vlanid2 >= 0)
					printf("%d ", packetArray[i].vlanid2);

				printf("| ");

				printf("%s: %s %s ", packetArray[i].ip.c_str(), packetArray[i].srcip.c_str(), packetArray[i].dstip.c_str());
				printf("%d | ", packetArray[i].ttl_hl);
				if (packetArray[i].protocol.compare("UDP") == 0)
					printf("%s: %d %d", packetArray[i].protocol.c_str(), packetArray[i].srcport, packetArray[i].dstport);
				else
					printf("%s: %d %d ", packetArray[i].protocol.c_str(), packetArray[i].srcport, packetArray[i].dstport);

				if (packetArray[i].protocol.compare("TCP") == 0) {
					printf("%u %u ", packetArray[i].seq, packetArray[i].ackN);

					(packetArray[i].cwr) ? printf("C") : printf(".");
					(packetArray[i].ece) ? printf("E") : printf(".");
					(packetArray[i].urg) ? printf("U") : printf(".");
					(packetArray[i].ack) ? printf("A") : printf(".");
					(packetArray[i].psh) ? printf("P") : printf(".");
					(packetArray[i].rst) ? printf("R") : printf(".");
					(packetArray[i].syn) ? printf("S") : printf(".");
					(packetArray[i].fin) ? printf("F") : printf(".");
				}

				if (packetArray[i].protocol.compare("ICMPv4") == 0)
					printf("%s", printICMP(packetArray[i].srcport, packetArray[i].dstport, 4).c_str());
				if (packetArray[i].protocol.compare("ICMPv6") == 0)
					printf("%s", printICMP(packetArray[i].srcport, packetArray[i].dstport, 6).c_str());
				printf("\n");
			}
		}
	}
	else {
		for (int i = 0; i < numberOfPackets; i++) {
			if (!packetArray[i].aggr.empty()) {
				if (!limit.empty())
					if((i+1) > stoi(limit))
						break;

				if (packetArray[i].protocol.compare("ICMPv4") == 0 || packetArray[i].protocol.compare("ICMPv6") == 0)
					if (aggrKey.compare("srcport") == 0 || aggrKey.compare("dstport") == 0) {
						continue;
					}
				printf("%s: %d %d\n", packetArray[i].aggr.c_str(), packetArray[i].packets, packetArray[i].size);
			}
		}
	}
}

bool fragmentMatch(packetRecord fragment1, packetRecord fragment2) {
	if (fragment1.srcip.empty() || fragment1.dstip.empty() || fragment1.protocol.empty())
		return false;
	if (fragment1.srcip.compare(fragment2.srcip) == 0)
		if (fragment1.dstip.compare(fragment2.dstip) == 0)
			if (fragment1.protocol.compare(fragment2.protocol) == 0)
				if (fragment1.id == fragment2.id)
					return true;
	return false;
}

void ipv4L4(packetRecord * record) {
	const struct udphdr *my_udp; // UDP pointer
	const struct tcphdr *my_tcp; // TCP pointer
	struct icmp *icmph; // ICMP pointer
	packetRecord empty;

	if (record->protocol.compare("ICMPv4") == 0) {
		icmph = (struct icmp *) (&record->ip4data[0]);
		
		record->srcport = icmph->icmp_type;
		record->dstport = icmph->icmp_code;
	}
	else if (record->protocol.compare("UDP") == 0) {
		my_udp = (struct udphdr *) (&record->ip4data[0]);
		
		// source, destination port
		record->srcport = ntohs(my_udp->source);
		record->dstport = ntohs(my_udp->dest);
	}
	else if (record->protocol.compare("TCP") == 0) {
		my_tcp = (struct tcphdr *) (&record->ip4data[0]);
		
		// source, destination port
		record->srcport = ntohs(my_tcp->source);
		record->dstport = ntohs(my_tcp->dest);

		// Seq number, Ack number
		record->seq = ntohs(my_tcp->seq);
		record->ackN = ntohs(my_tcp->ack_seq);
		int index = 13;

		((record->ip4data[index] & 0b10000000) == 0b10000000) ? (record->cwr = true) : (record->cwr = false);
		((record->ip4data[index] & 0b01000000) == 0b01000000) ? (record->ece = true) : (record->ece = false);
		((record->ip4data[index] & 0b00100000) == 0b00100000) ? (record->urg = true) : (record->urg = false);
		((record->ip4data[index] & 0b00010000) == 0b00010000) ? (record->ack = true) : (record->ack = false);
		((record->ip4data[index] & 0b00001000) == 0b00001000) ? (record->psh = true) : (record->psh = false);
		((record->ip4data[index] & 0b00000100) == 0b00000100) ? (record->rst = true) : (record->rst = false);
		((record->ip4data[index] & 0b00000010) == 0b00000010) ? (record->syn = true) : (record->syn = false);
		((record->ip4data[index] & 0b00000001) == 0b00000001) ? (record->fin = true) : (record->fin = false);
	}
}

void processPacket(packetRecord * record, int ip_type, string net_type) {
	int shift;
	if (net_type.compare("ETHER") == 0) shift = 0;
	if (net_type.compare("VLAN") == 0) shift = 4;
	if (net_type.compare("VLANad") == 0) shift = 8;
	const struct tcphdr *my_tcp; // TCP pointer
	const struct udphdr *my_udp; // UDP pointer
	struct icmp *icmph; // ICMP pointer
	u_int size_ip;
	packetRecord empty;

	// Dst mac
	char buf[6];
	sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x ",
	(int)(unsigned char)packet[0],
	(int)(unsigned char)packet[1],
	(int)(unsigned char)packet[2],
	(int)(unsigned char)packet[3],
	(int)(unsigned char)packet[4],
	(int)(unsigned char)packet[5]);
	record->dstmac = buf;
	record->dstmac.pop_back();

	// Src mac
	sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x ",
	(int)(unsigned char)packet[6],
	(int)(unsigned char)packet[7],
	(int)(unsigned char)packet[8],
	(int)(unsigned char)packet[9],
	(int)(unsigned char)packet[10],
	(int)(unsigned char)packet[11]);
	record->srcmac = buf;
	record->srcmac.pop_back();

	// 12 bits VLAN ID
	if (net_type.compare("VLAN") == 0) {
		if (packet[13] > 15)
			record->vlanid1 = packet[15] + (packet[14] << 8);
		else
			record->vlanid1 = packet[15] + (packet[14] << 8) + (packet[13] << 16);
	}
	if (net_type.compare("VLANad") == 0) {
		if (packet[13] > 15)
			record->vlanid1 = packet[15] + (packet[14] << 8);
		else
			record->vlanid1 = packet[15] + (packet[14] << 8) + (packet[13] << 16);

		if (packet[17] > 15)
			record->vlanid2 = packet[19] + (packet[18] << 8);
		else
			record->vlanid2 = packet[19] + (packet[18] << 8) + (packet[17] << 16);
	}
	
	if (ip_type == 4) {
		struct ip *my_ipv4; // Pointer to IP header
		my_ipv4 = (struct ip*) (packet + SIZE_ETHERNET + shift);
		record->ip_off = ((((packet[SIZE_ETHERNET + shift + 6] & 0b00011111) << 3) * 256) + (packet[SIZE_ETHERNET + shift + 7] << 3));
		record->ip_len = (packet[SIZE_ETHERNET + 2 + shift] << 8) + (packet[SIZE_ETHERNET + 3 + shift]);
		record->mf = packet[20 + shift]&0b00100000;

		if (record->mf > 0)
			record->mf = 1;

		size_ip = my_ipv4->ip_hl*4;
		record->ip = "IPv4";

		// Fragment ip id
		record->id = my_ipv4->ip_id;
		record->ip_hl = size_ip;
		record->data = record->ip_len - record->ip_hl;

		// Src ip, Dst ip, ttl
		record->srcip = inet_ntoa(my_ipv4->ip_src);
		record->dstip = inet_ntoa(my_ipv4->ip_dst);
		record->ttl_hl = my_ipv4->ip_ttl;

		if (record->mf == 1 || record->ip_off > 0) {
			for (int i = 0; i < record->data; i++) {
				unsigned char temp = packet[i + SIZE_ETHERNET + shift + 20];
				record->ip4data.push_back(temp);
			}
			record->frag = true;
		}

		switch (my_ipv4->ip_p) {
			case 1: // ICMP protocol
				record->protocol = "ICMPv4";
				icmph = (struct icmp *) (packet + SIZE_ETHERNET + size_ip + shift);

				record->srcport = icmph->icmp_type;
				record->dstport = icmph->icmp_code;
				break;
			case 6: // TCP protocol
				my_tcp = (struct tcphdr *) (packet+SIZE_ETHERNET+size_ip + shift);

				// source, destination port
				record->protocol = "TCP";
				record->srcport = ntohs(my_tcp->source);
				record->dstport = ntohs(my_tcp->dest);
				break;
			case 17: // UDP protocol
				my_udp = (struct udphdr *) (packet+SIZE_ETHERNET+size_ip + shift);

				// source, destination port
				record->protocol = "UDP";
				record->srcport = ntohs(my_udp->source);
				record->dstport = ntohs(my_udp->dest);
				break;
			default:
				record->protocol = "UNKNOWN";
				break;
		}
	}
	else if (ip_type == 6) {
		struct ip6_hdr *my_ipv6; // Pointer to IPv6 header
		my_ipv6 = (struct ip6_hdr*) (packet+SIZE_ETHERNET + shift);
		size_ip = my_ipv6->ip6_ctlun.ip6_un1.ip6_un1_hlim;
		char str[128];

		// Src, dest IPv6
		record->ip = "IPv6";
		record->srcip = inet_ntop(AF_INET6, &(my_ipv6->ip6_src), str, 128);
		record->dstip = inet_ntop(AF_INET6, &(my_ipv6->ip6_dst), str, 128);
		record->ttl_hl = size_ip;

		char nextheader = (char)packet[SIZE_ETHERNET + shift + 6]; // Next Header

		while(1) {
			if (nextheader == 0) { // Hop-by-hop options (8 octets + headerlen)
				nextheader = (char)packet[SIZE_ETHERNET + shift + 40];
				shift += 8 + (int)packet[SIZE_ETHERNET + shift + 41];
			}
			else if (nextheader == 60) { // Destination options (8 octets + headerlen)
				nextheader = (char)packet[SIZE_ETHERNET + shift + 40];
				shift += 8 + (int)packet[SIZE_ETHERNET + shift + 41];
			}
			else if (nextheader == 43) { // Routing (8 octets + headerlen)
				nextheader = (char)packet[SIZE_ETHERNET + shift + 40];
				shift += 8 + (int)packet[SIZE_ETHERNET + shift + 41];
			}
			else if (nextheader == 44) { // Fragment (8 octets)
				nextheader = (char)packet[SIZE_ETHERNET + shift + 40];
				shift += 8;
			}
			else
				break;
		}

		switch (nextheader) {
			case 58: // ICMP protocol
				record->protocol = "ICMPv6";
				icmph = (struct icmp *) (packet + SIZE_ETHERNET + 40 + shift);

				record->srcport = icmph->icmp_type;
				record->dstport = icmph->icmp_code;
				break;
			case 6: // TCP protocol
				my_tcp = (struct tcphdr *) (packet+SIZE_ETHERNET + 40 + shift);

				// source, destination port
				record->protocol = "TCP";
				record->srcport = ntohs(my_tcp->source);
				record->dstport = ntohs(my_tcp->dest);
				break;
			case 17: // UDP protocol
				my_udp = (struct udphdr *) (packet + SIZE_ETHERNET + 40 + shift);

				// source, destination port
				record->protocol = "UDP";
				record->srcport = ntohs(my_udp->source);
				record->dstport = ntohs(my_udp->dest);
				break;
			default:
				record->protocol = "UNKNOWN";
				break;
		}
	}

	if (record->protocol.compare("TCP") == 0) {
		// Seq number, Ack number
		record->seq = ntohl(my_tcp->seq);
		record->ackN = ntohl(my_tcp->ack_seq);

		int index = 47 + shift;
		if (ip_type == 6) index += 20;

		((packet[index] & 0b10000000) == 0b10000000) ? (record->cwr = true) : (record->cwr = false);
		((packet[index] & 0b01000000) == 0b01000000) ? (record->ece = true) : (record->ece = false);
		((packet[index] & 0b00100000) == 0b00100000) ? (record->urg = true) : (record->urg = false);
		((packet[index] & 0b00010000) == 0b00010000) ? (record->ack = true) : (record->ack = false);
		((packet[index] & 0b00001000) == 0b00001000) ? (record->psh = true) : (record->psh = false);
		((packet[index] & 0b00000100) == 0b00000100) ? (record->rst = true) : (record->rst = false);
		((packet[index] & 0b00000010) == 0b00000010) ? (record->syn = true) : (record->syn = false);
		((packet[index] & 0b00000001) == 0b00000001) ? (record->fin = true) : (record->fin = false);
	}
}

packetRecord * aggrPackets(packetRecord * packetArray) {
	packetRecord * agregovane = new packetRecord[numberOfPackets+1];
	string temp;

	for (int i = 0; i < numberOfPackets; i++) {
		if (aggrKey.compare("srcmac") == 0)
			temp = packetArray[i].srcmac;
		if (aggrKey.compare("dstmac") == 0)
			temp = packetArray[i].dstmac;
		if (aggrKey.compare("srcip") == 0)
			temp = packetArray[i].srcip;
		if (aggrKey.compare("dstip") == 0)
			temp = packetArray[i].dstip;
		if (aggrKey.compare("srcport") == 0)
			temp = to_string(packetArray[i].srcport);
		if (aggrKey.compare("dstport") == 0)
			temp = to_string(packetArray[i].dstport);
		
		for (int j = 0; j < numberOfPackets; j++) {
			if (agregovane[j].aggr.compare(temp) == 0) {
				agregovane[j].size += packetArray[i].size;
				agregovane[j].packets++;
				break;
			}
			if (j+1 == numberOfPackets) {
				for (int k = 0; k < numberOfPackets; k++) {
					if (agregovane[k].aggr.empty()) {
						agregovane[k].aggr = temp;
						agregovane[k].size = packetArray[i].size;
						agregovane[k].packets = 1;
						agregovane[k].protocol = packetArray[i].protocol;
						break;
					}
				}
			}
		}
	}
	delete [] packetArray;
	return agregovane;
}

void sortPackets(packetRecord * packetArray) {
	if (sortKey.compare("packets") == 0 && !aggrKey.empty()) {
		for (int i = 0; i < numberOfPackets; i++) {
			for (int j = 0; j < numberOfPackets-i; j++) {
				if (packetArray[j].packets < packetArray[j+1].packets) {
					packetArray[numberOfPackets] = packetArray[j];
					packetArray[j] = packetArray[j+1];
					packetArray[j+1] = packetArray[numberOfPackets];
				}
			}
		}
	}
	else if (sortKey.compare("bytes") == 0) {
		for (int i = 0; i < numberOfPackets; i++) {
			for (int j = 0; j < numberOfPackets-i; j++) {
				if (packetArray[j].size < packetArray[j+1].size) {
					packetArray[numberOfPackets] = packetArray[j];
					packetArray[j] = packetArray[j+1];
					packetArray[j+1] = packetArray[numberOfPackets];
				}
			}
		}
	}
	else {
		for (int i = 0; i < numberOfPackets; i++) {
			for (int j = 0; j < numberOfPackets-i; j++) {
				if (packetArray[j].number > packetArray[j+1].number) {
					packetArray[numberOfPackets] = packetArray[j];
					packetArray[j] = packetArray[j+1];
					packetArray[j+1] = packetArray[numberOfPackets];
				}
			}
		}
	}
}

void processArgs(int argc, char *argv[]) {
	if (argv[1] == NULL)
		errExit("No arguments.", 1);

	bool aggrKeyBool = false;
	bool sortKeyBool = false;
	bool limitBool = false;
	bool filterBool = false;
	int filePositionStartInArgv = 0;

	for(int i = 1; i < argc; i++) {
		string argument = argv[i];

		// Help
		if (argument.compare("-h") == 0 && i == 1 && argc == 2)
			printHelp();
		else if (argument.compare("-h") == 0)
			errExit("Invalid arguments.", 1);
			
		// Aggr-key
		else if (argument.compare("-a") == 0) {
				if (!aggrKeyBool)
					aggrKeyBool = true;
				else
					errExit("Invalid arguments, -a more than once.", 1);
		}
		else if (aggrKeyBool && aggrKey.empty()) {
			aggrKey = argument;
			if (aggrKey.compare("srcmac") != 0 && aggrKey.compare("dstmac") != 0 &&
				aggrKey.compare("srcip") != 0 && aggrKey.compare("dstip") != 0 &&
				aggrKey.compare("srcport") != 0 && aggrKey.compare("dstport") != 0)
				errExit("Invalid aggr-key.", 1);
		}

		// Sort-key
		else if (argument.compare("-s") == 0) {
				if (!sortKeyBool)
					sortKeyBool = true;
				else
					errExit("Invalid arguments, -s more than once.", 1);
		}
		else if (sortKeyBool && sortKey.empty()) {
			sortKey = argument;
			if (sortKey.compare("packets") != 0 && sortKey.compare("bytes") != 0)
				errExit("Invalid sort-key.", 1);
		}

		// Limit
		else if (argument.compare("-l") == 0) {
				if (!limitBool)
					limitBool = true;
				else
					errExit("Invalid arguments, -l more than once.", 1);
		}
		else if (limitBool && limit.empty()) {
			for (unsigned int i = 0; i < argument.length(); i++) {
				char ch = argument[i];
				if (!(ch > 47 && ch < 58))
					errExit("Invalid limit value number.", 1);
			}
			if (stoi(argument) < 0)
				errExit("Invalid limit value, lower than zero.", 1);
			limit = argument;
		}

		// Filter-expression
		else if (argument.compare("-f") == 0) {
				if (!filterBool)
					filterBool = true;
				else
					errExit("Invalid arguments, -f more than once.", 1);
		}
		else if (filterBool && filter.empty())
			filter = argument;
		else {
			int temp = i + 1;
			if (temp < argc) {
				string k = argv[temp];
				if (k.compare("-a") == 0 || k.compare("-s") == 0 ||
				k.compare("-l") == 0 || k.compare("-f") == 0)
					errExit("Invalid arguments.", 1);
			}

			if (filePositionStartInArgv == 0)
				filePositionStartInArgv = i;
			numberOfFiles++;
		}
	}

	if (numberOfFiles == 0)
		errExit("No files specified.", 1);

	string * array = new string[numberOfFiles];
	int j = 0;
	for (int i = filePositionStartInArgv; i < argc; i++) {
		array[j] = argv[i];
		j++;
	}
	for (int i = 0; i < numberOfFiles; i++) {
		for (int j = i+1; j < numberOfFiles; j++) {
			if (array[i].compare(array[j]) == 0)
				errExit("Same file multiple times as a parameter!", 1);
		}
	}
	files = array;
}

void errExit(string err, int code = 0) {
	fprintf(stderr, "%s\n", err.c_str());
	if (code != 0)
		exit(code);
}

string printICMP(int type, int code, int version) {
	string message = "";

	if (version == 4) {
		if (type == 3) {
			message = "destination unreachable";
			if (code == 0) message += " net unreachable";
			if (code == 1) message += " host unreachable";
			if (code == 2) message += " protocol unreachable";
			if (code == 3) message += " port unreachable";
			if (code == 4) message += " fragmentation needed and DF set";
			if (code == 5) message += " source route failed";
		}
		if (type == 11) {
			message = "time exceeded";
			if (code == 0) message += " time to live exceeded in transit";
			if (code == 1) message += " fragment reassembly time exceeded";
		}
		if (type == 12) {
			message = "parameter problem";
			if (code == 0) message += " pointer indicates the error";
		}
		if (type == 4)
			message = "source quench";
		if (type == 5) {
			message = "redirect";
			if (code == 0) message += " redirect datagrams for the network";
			if (code == 1) message += " redirect datagrams for the host";
			if (code == 2) message += " redirect datagrams for the type of service and network";
			if (code == 3) message += " redirect datagrams for the type of service and host";
		}
		if (type == 8)
			message = "echo";
		if (type == 0)
			message = "echo reply";
		if (type == 13)
			message = "timestamp";
		if (type == 14)
			message = "timestamp reply";
		if (type == 15)
			message = "information request";
		if (type == 16)
			message = "information reply";
	}
	if (version == 6) {
		if (type == 1) {
			message = "destination unreachable";
			if (code == 0) message += " no route to destination";
			if (code == 1) message += " communication with destination administratively prohibited";
			if (code == 2) message += " beyond scope of source address";
			if (code == 3) message += " address unreachable";
			if (code == 4) message += " port unreachable";
			if (code == 5) message += " source address failed ingress/egress policy";
			if (code == 6) message += " reject route to destination";
		}
		if (type == 2)
			message = "packet too big";
		if (type == 3) {
			message = "time exceeded";
			if (code == 0) message += " hop limit exceeded in transit";
			if (code == 1) message += " fragment reassembly time exceeded";
		}
		if (type == 4) {
			message = "parameter problem";
			if (code == 0) message += " erroneous header field encountered";
			if (code == 1) message += " unrecognized next header type encountered";
			if (code == 2) message += " unrecognized IPv6 option encountered";
		}
		if (type == 128)
			message = "echo request";
		if (type == 129)
			message = "echo reply";
	}
	return message;
}

void printHelp() {
	string hints = "";
	hints += "\nisashark [-h] [-a aggr-key] [-s sort-key] [-l limit] [-f filter-expression] file\n\n";
	hints += "-h Prints out help and terminates the program.\n\n";
	hints += "-a aggr-key Turn on aggregation by aggr-key, which can be srcmac for source MAC\n";
	hints += "   address or dstmac for destination MAC address, srcip for soure IP, dstip for\n";
	hints += "   destination IP address, srcport or dstport for aggregation by port number.\n\n";
	hints += "-s sort-key Sorting by sort-key, which can be packets (number of packets) or bytes\n";
	hints += "   (number of bytes of packets). Sorting can be applied also to aggregated items.\n\n";
	hints += "-l limit Decimal positive number of packets printed to stdout.\n\n";
	hints += "-f filter-expression Analyse only packets suitable for this filter. More info in\n";
	hints += "   manual page of pcap-filter.\n\n";
	hints += "file Path to file in pcap format (readable by libcap library). One or more files can \n";
	hints += "     be provided at once, separated by space.\n";
	fprintf(stdout, "%s\n", hints.c_str());
	exit(0);
}