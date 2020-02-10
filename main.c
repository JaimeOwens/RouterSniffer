#include<sys/param.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<unistd.h>
#include<signal.h>
#include<errno.h>
#include "process.h"

int initdaemon(void) {
	int pid;
	int i;
	signal(SIGTTOU,SIG_IGN);
	signal(SIGTTIN,SIG_IGN);
	signal(SIGTSTP,SIG_IGN);
	signal(SIGHUP,SIG_IGN);
	pid = fork();
	if(pid > 0) {
		exit(0);
	} else if(pid < 0) {
		return -1;
	}
	setsid();
	pid=fork();
	if( pid > 0) {
		exit(0);
	} else if( pid< 0) {
		return -1;
	}
	for(i=0;i< NOFILE;close(i++));
	chdir("/");
	umask(0);
	signal(SIGCHLD,SIG_IGN);
	return 0;
}

int main() {
	initdaemon();
	
	char errBuf[PCAP_ERRBUF_SIZE]; /*error Buff*/
	struct pcap_pkthdr packet;  /*The header that pcap gives us*/
	pcap_t *dev; /*network interface*/
	bpf_u_int32 netp, maskp;
	char *net, *mask;
	struct in_addr addr;
	int ret;

	/*look up device network addr and mask*/
	if(pcap_lookupnet(DEVICE, &netp, &maskp, errBuf)) {
		printf("get net failure\n");
		exit(1);
	}
	addr.s_addr = netp;
	net = inet_ntoa(addr);
	printf("network: %s\n", net);

	addr.s_addr = maskp;
	mask = inet_ntoa(addr);
	printf("mask: %s\n", mask);

	/*open network device for packet capture*/
	dev = pcap_open_live(DEVICE, 65536, 1, 0, errBuf);
	if(NULL == dev) {
		printf("open %s failure\n", DEVICE);
		exit(1);
	}

	/*process packets from a live capture or savefile*/
	pcap_loop(dev, 0, get_packet, NULL);

	/*close device*/
	pcap_close(dev);

	return 0;
}

