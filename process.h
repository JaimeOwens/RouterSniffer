#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <time.h>
#include "mysqlhd.h"

#define DEVICE "eth0"
#define URL_MAX_LEN 2048
#define MAX_HOST_LEN 1024
#define MAX_GET_LEN 2048
#define MAX_LINE_LEN 1024

#define get_u_int8_t(X,O)  (*(uint8_t *)(((uint8_t *)X) + O))
#define get_u_int16_t(X,O)  (*(uint16_t *)(((uint8_t *)X) + O))
#define get_u_int32_t(X,O)  (*(uint32_t *)(((uint8_t *)X) + O))
#define get_u_int64_t(X,O)  (*(uint64_t *)(((uint8_t *)X) + O))

struct request{
	char eth_dstmac[18];
	char eth_srcmac[18];
	int ip_version;
	int ip_total_len;
	int ip_protocol;
	char *ip_dstaddr;
	char *ip_srcaddr;
	int tcp_dstport;
	int tcp_srcport;
	char http_host[64];
	char http_url[1024];
	int create_time;
};

void show_ethhdr(struct ethhdr *eth) {
	printf("----------------eth---------------------\n");
	printf("destination eth addr: %02x:%02x:%02x:%02x:%02x:%02x\n",
	       eth->h_dest[0], eth->h_dest[1],
	       eth->h_dest[2], eth->h_dest[3],
	       eth->h_dest[4], eth->h_dest[5]);
	printf("source eth addr: %02x:%02x:%02x:%02x:%02x:%02x\n",
	       eth->h_source[0], eth->h_source[1],
	       eth->h_source[2], eth->h_source[3],
	       eth->h_source[4], eth->h_source[5]);
	printf("protocol is: %04x\n", ntohs(eth->h_proto));
}

void show_iphdr(struct iphdr *ip) {
	struct in_addr addr;
	printf("----------------ip----------------------\n");
	printf("version: %d\n", ip->version);
	printf("head len: %d\n", ip->ihl * 4);
	printf("total len: %d\n", ntohs(ip->tot_len));
	printf("ttl: %d\n", ip->ttl);
	printf("protocol: %d\n", ip->protocol);
	printf("check: %x\n", ip->check);
	addr.s_addr = ip->saddr;
	printf("saddr: %s\n", inet_ntoa(addr));
	addr.s_addr = ip->daddr;
	printf("daddr: %s\n", inet_ntoa(addr));
}

void show_tcphdr(struct tcphdr *tcp) {
	printf("----------------tcp---------------------\n");
	printf("tcp len: %d\n", sizeof(struct tcphdr));
	printf("tcp->doff: %d\n", tcp->doff * 4);
	printf("source port: %d\n", ntohs(tcp->source));
	printf("dest port: %d\n", ntohs(tcp->dest));
	printf("sequence number: %d\n", ntohs(tcp->seq));
	printf("ack sequence: %d\n", ntohs(tcp->ack_seq));
}

void getKeyValue(char *line,char *info_id){
	char *p = line;
	char key[64];
	char value[2048];
	char message[2048];
	int flag = 0, cnt = 0 ;
	memset(key,0,sizeof(key));
	memset(value,0,sizeof(value));
	while(*p != '\0'){
		if(*p == ':'){
			flag = 1;
			cnt = 0;
			p += 2;
		}
		if(!flag){
			key[cnt] = *p;
			cnt++;
		}
		else{
			value[cnt] = *p;
			cnt++;
		}
		p++;
	}
	//printf("%s\n",key);
	//printf("%s\n",value);
	if(strlen(key)){
		char field[64] = "header_key,header_value,info_id";
		sprintf(message,"'%s','%s','%s'",key,value,info_id);
		insert_msg("http_header",field,message);
	}
	memset(key,0,sizeof(key));
	memset(value,0,sizeof(value));
}

void save_as_request(char *ip_src_addr,char *ip_dst_addr, char *host, char *get, char *method){
	char message[1024];
	char field[128] = "src_ip,dest_ip,method,http_host,http_url,http_url_hash";
	sprintf(message,"'%s','%s','%s','%s','%s',md5('%s')",
					ip_src_addr,ip_dst_addr,method,host,get,get);
	insert_msg("http_info",field,message);
	
	/*printf("----------------HTTP---------------------\n");
	printf("MAC DST:%s\n",rst->eth_dstmac);
	printf("MAC SRC:%s\n",rst->eth_srcmac);
	printf("IP VER:%d\n",rst->ip_version);
	printf("IP TOTALLEN:%d\n",rst->ip_total_len);
	printf("IP PROTOCOL:%d\n",rst->ip_protocol);
	printf("IP DST ADDR:%s\n",ip_src_addr);
	printf("IP SRC ADDR:%s\n",ip_dst_addr);
	printf("TCP DST PORT:%d\n",rst->tcp_dstport);
	printf("TCP SRC PORT:%d\n",rst->tcp_srcport);
	printf("HTTP HOST:%s\n",host);
	printf("HTTP URL:%s\n",get);
	printf("HTTP CREATE TIME:%d\n",create_time);*/
	
	return;
}

void parse_http_head(char *ip_src_addr,char *ip_dst_addr, const u_char *payload, int payload_len) {
	int line_len;
	int ustrlen;
	int hstrlen; //"host: "
	int hostlen;
	int getlen;
	char host[MAX_HOST_LEN];
	char get[MAX_GET_LEN];
	char line[MAX_LINE_LEN];
	char method[8];
	int a, b;
	int cnt = 0;
	int flag = 0;
	
	/*filter get packet*/
	if(memcmp(payload, "GET ", 4) && memcmp(payload, " POST", 5)) {
		return;
	}
	else if(!memcmp(payload, "GET ", 4)){
		flag = 1;
		strcpy(method,"GET");
	}
	else if(!memcmp(payload, " POST", 5)){
		flag = 2;
		strcpy(method,"POST");
	}
	memset(host,0,sizeof(host));
	memset(get,0,sizeof(get));
	char info_id[5];
	get_id(info_id);
	printf("info_id:%s\n",info_id);
	for(a = 0, b = 0; a < payload_len - 1; a++) {
		if (get_u_int16_t(payload, a) == ntohs(0x0d0a)) {
			line_len = (u_int16_t)(((unsigned long) &payload[a]) - ((unsigned long)&payload[b]));
			if(flag == 1){
				if (line_len >= (9 + 4)
					&& memcmp(&payload[line_len - 9], " HTTP/1.", 8) == 0) {
					memcpy(get, payload + 4, line_len - 13); //"GET  HTTP/1.x" 13bit
					getlen = line_len - 13;
				}
			}
			if(flag==2){
				if (line_len >= (9 + 5)
					&& memcmp(&payload[line_len - 9], " HTTP/1.", 8) == 0) {
					memcpy(get, payload + 5, line_len - 14); //"POST  HTTP/1.x" 14bit
					getlen = line_len - 14;
				}		
			}
			//get url host of pcaket
			if (line_len > 6
					&& memcmp(&payload[b], "Host:", 5) == 0) {
					if(*(payload + b + 5) == ' ') {
						hstrlen = b + 6;
					} else {
						hstrlen = b + 5;
					}
					hostlen = a - hstrlen;
					memcpy(host, payload + hstrlen, (a - hstrlen));
					save_as_request(ip_src_addr, ip_dst_addr, host, get, method);
				}
			if(cnt > 1){
				memset(line,0,sizeof(line));
				memcpy(line,payload+b,line_len);
				getKeyValue(line,info_id);
			}
			cnt += 1;
			b = a + 2;
		}
	}
	return;
}

int prase_packet(const u_char *buf,  int caplen) {
	uint16_t e_type;
	uint32_t offset;
	int payload_len;
	const u_char *tcp_payload;

	/* ether header */
	struct ethhdr *eth = NULL;
	eth = (struct ethhdr *)buf;
	e_type = ntohs(eth->h_proto);
	offset = sizeof(struct ethhdr);
	//show_ethhdr(eth);
	
	/*vlan 802.1q*/
	while(e_type == ETH_P_8021Q) {
		e_type = (buf[offset+2] << 8) + buf[offset+3];
		offset += 4;
	}
	if (e_type != ETH_P_IP) {
		return -1;
	}

	/* ip header */
	struct iphdr *ip = (struct iphdr *)(buf + offset);
	e_type = ntohs(ip->protocol);
	offset += sizeof(struct iphdr);
	struct in_addr addr;
	char ip_src_addr[40], ip_dst_addr[40];
	addr.s_addr = ip->saddr;
	strcpy(ip_src_addr, inet_ntoa(addr));
	addr.s_addr = ip->daddr;
	strcpy(ip_dst_addr, inet_ntoa(addr));
	//show_iphdr(ip);
	
	if(ip->protocol != IPPROTO_TCP) {
		return -1;
	}
	/*tcp header*/
	struct tcphdr *tcp = (struct tcphdr *)(buf + offset);
	offset += (tcp->doff << 2);
	payload_len = caplen - offset;
	tcp_payload = (buf + offset);
	//show_tcphdr(tcp);
	
	/*prase http header*/
	parse_http_head(ip_src_addr, ip_dst_addr, tcp_payload, payload_len);
	return 0;
}

void get_packet(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	//static int count = 0;
	//printf("\n----------------------------------------\n");
	//printf("\t\tpacket %d\n", count);
	//printf("----------------------------------------\n");
	//printf("Packet id: %d\n", count);
	//printf("Packet length: %d\n", pkthdr->len);
	//printf("Number of bytes: %d\n", pkthdr->caplen);
	//printf("Recieved time: %s\n", ctime((const time_t *)&pkthdr->ts.tv_sec));
	prase_packet(packet, pkthdr->len);
	//count++;
}










