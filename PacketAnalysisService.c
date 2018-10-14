/**
	@Month of the last update : 2015/11
*/


/*
	> how to compile
	gcc -o PacketAnlysisService PacketAnlysisService.c -lmysqlclient -lpcap
*/

#include <stdio.h>
#include <stdlib.h> // exit(), malloc(), system()
#include <string.h> // strcpy()
#include <arpa/inet.h> // inet_ntoa(), ntohs()
#include <net/ethernet.h> // struct ether_header
#include <netinet/in.h> // struct in_addr
#include <netinet/ip.h> // struct ip
#include <pcap/pcap.h>
#include <errno.h> // errno
#include <signal.h> // struct sigaction
#include <sys/time.h> // struct itimerval
#include "/usr/include/mysql/mysql.h"

// Hash Table Size
#define HASH_TABLE_SIZE 100000 // Set 100000

// Hash Struct
typedef struct _SrcInfo {
	char* address;
	int count;
	struct _SrcInfo *next;
} SrcInfo;

SrcInfo* HashTable[HASH_TABLE_SIZE]; // Hash Table
MYSQL conn; // MySQL Global Variable
int receivedPacket; // Number of received packet
int permittedLimit; // Block IP Address Condition
int packetCollectionTime;
int flag = 0; // program exit flag


// Program Variable Setting
void Initialization();

// Timer function
void TimerHandler();
void PacketCollectionTimer();

// Packet function
void CollectPacket();
void ExtractIP(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet);

// Hash Algorithm function
void InsertAddress(char* address);
int HashFunction(char* address);

// Block IP function
void BlockIP();

// Shell Command function
void ShellCmd(char* address);

// MySQL Connection function
void InitDB();
void InsertDB(char* address);
void CloseDB();


int main(void)
{
	printf("Initialization ...\n");
	Initialization();

	printf("CollectPacket ...\n");
	PacketCollectionTimer();
	CollectPacket();
	flag = 1;

	printf("Initialization Database ...\n");
	InitDB();
	
	printf("Block IP Address Check ...\n");
	BlockIP();

	printf("Close Database ...\n");
	CloseDB();

	return 0;
}


void Initialization()
{
	permittedLimit = 120; // Set 120
	receivedPacket = 5000; // Set 5000
	packetCollectionTime = 90; // Set 90
}

void TimerHandler()
{
	if(flag == 0){
		printf("Time Over!\n");
		exit(1);
	}
}

void PacketCollectionTimer()
{
	struct sigaction sa;
	struct itimerval timer;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = &TimerHandler;
	sigaction(SIGVTALRM, &sa, NULL);

	timer.it_value.tv_sec = packetCollectionTime;
	timer.it_value.tv_usec = 0;

	timer.it_interval.tv_sec = 0;
	timer.it_interval.tv_usec = 0;

	setitimer(ITIMER_VIRTUAL, &timer, NULL);
}

void CollectPacket()
{
	// pcap_lookupnet variable
	int ret;
	char *dev = "p4p1";
	char *net;
	char errbuf[PCAP_ERRBUF_SIZE]; // error message
	bpf_u_int32 netp; // ip
	bpf_u_int32 maskp; // subnet mask
	struct in_addr addr;

	// pcap_open_live variable
	pcap_t *pcd;

	// pcap_compile variable
	struct bpf_program fp;

	// pcap_lookupnet function
	ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
	if(ret == -1){
		printf("%s\n", errbuf);
		exit(1);
	}

	addr.s_addr = netp;
	net = inet_ntoa(addr); // dot notation of the network address

	if(net == NULL){
		perror("inet_ntoa");
		exit(1);
	}

	// printf("NET: %s\n", net);

	// pcap_open_live function
	pcd = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);
	if(pcd == NULL){
		printf("%s\n", errbuf);
		exit(1);
	}
	
	// pcap_compile function
	if(pcap_compile(pcd, &fp, "port 53", 0, netp) == -1){ // Set port 53
		printf("pcap_compile() error\n");
		exit(1);
	}

	// pcap_setfilter function
	if(pcap_setfilter(pcd, &fp) == -1){
		printf("setfilter() error\n");
		exit(0);
	}

	// pcap_loop function
	pcap_loop(pcd, receivedPacket, ExtractIP, NULL); // packet total count
}

void ExtractIP(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	struct ether_header *ep;
	struct ip *iph;
	static int packetCount = 0;

	// Get Ethernet header
	ep = (struct ether_header *) packet;
	
	// To get IP header, offset as size of Ethernet header
	packet += sizeof(struct ether_header);

	// Check IP Packet
	if(ntohs(ep->ether_type) == ETHERTYPE_IP){
		
		iph = (struct ip *) packet;
	
		/*
		// Packet Count
		packetCount++;
		printf("[%d]\n", packetCount);
		printf("Src Address : %s\n", inet_ntoa(iph->ip_src));
		printf("Dst Address : %s\n\n", inet_ntoa(iph->ip_dst));
		*/

		// Check UDP Protocol && Check Destination Point 1.234.83.38
		if((iph->ip_p == IPPROTO_UDP) && !(strcmp(inet_ntoa(iph->ip_dst), "1.234.83.38"))){ // Set UDP
			
			/*
			// Packet Count
			packetCount++;
			printf("[%d]\n", packetCount);
			printf("Src Address : %s\n", inet_ntoa(iph->ip_src));
			printf("Dst Address : %s\n\n", inet_ntoa(iph->ip_dst));
			*/

			// register IP Address in Hash Table
			InsertAddress(inet_ntoa(iph->ip_src));
		}
	}
}

void InsertAddress(char* address)
{
	int key = HashFunction(address);
	char* newAddress;
	SrcInfo* frontChaser = HashTable[key]; 
	SrcInfo* backChaser = NULL;
	SrcInfo* newSrcInfo;

	while(frontChaser != NULL){
		backChaser = frontChaser;

		// Case 1. exist address
		if(strcmp(address, backChaser->address) == 0){
			backChaser->count += 1;
			return ;
		}
		frontChaser = frontChaser->next;
	}

	// Case 2. not exist address
	newAddress = (char*)malloc(sizeof(char)*(strlen(address)+1));
	strcpy(newAddress, address);
	
	newSrcInfo = (SrcInfo*)malloc(sizeof(SrcInfo));
	newSrcInfo->count = 1;
	newSrcInfo->next = NULL;	
	newSrcInfo->address = newAddress;

	if(backChaser != NULL)
		backChaser->next = newSrcInfo;
	else
		HashTable[key] = newSrcInfo;
}

int HashFunction(char* address)
{
	int i, j, sum;
	int HashIdx = 0;

	for(i=0; i<strlen(address); i++){
		// decrease of collision effect
		for(j=0, sum=1; j<i; j++)
			sum = sum * 2;

		HashIdx += address[i] * sum;
	}

	return HashIdx % HASH_TABLE_SIZE;
}

void BlockIP()
{
	int i;
	SrcInfo* frontChaser;
	SrcInfo* backChaser;

	for(i=0; i<HASH_TABLE_SIZE; i++){
		frontChaser = HashTable[i];
		
		while(frontChaser != NULL){
			backChaser = frontChaser;
			
			if(backChaser->count > permittedLimit){
				printf("Block IP Address .................. [%s]\n", backChaser->address);
				ShellCmd(backChaser->address);
				InsertDB(backChaser->address);
			}

			frontChaser = frontChaser->next;
		}
	}
}

void ShellCmd(char* address)
{
	char deleteScript[80] = "iptables -D INPUT -s ";
	char appendScript[80] = "iptables --insert INPUT 4 -s ";

	strcat(deleteScript, address);
	strcat(deleteScript, " -p udp --dport 53 -j DROP");
	
	strcat(appendScript, address);
	strcat(appendScript, " -p udp --dport 53 -j DROP");

	system(deleteScript);
	system(appendScript);
}

void InitDB()
{
	mysql_init(&conn);
	
	if(!mysql_real_connect(&conn, "1.234.83.38", "DMSuser", "inimax0703#", "DMS", 3306, NULL, 0)){
		printf("mysql_real_connect() error\n");
		exit(1);
	}
}

void InsertDB(char* address)
{
	char deleteScript[60] = "delete from BlockIP where ip=\"";
	char insertScript[60] = "insert into BlockIP (ip) values (\"";
	
	strcat(deleteScript, address);
	strcat(deleteScript, "\"");
	
	strcat(insertScript, address);
	strcat(insertScript, "\")");

	if(mysql_query(&conn, deleteScript)){
		printf("mysql_query() error\n");
		exit(1);
	}

	if(mysql_query(&conn, insertScript)){
		printf("mysql_query() error\n");
		exit(1);
	}
}

void CloseDB(){
	mysql_close(&conn);
}

