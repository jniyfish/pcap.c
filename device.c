/*
	Packet sniffer using libpcap library
*/
#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset

#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void process_ip_packet(const u_char * , int);
void print_ip_packet(const u_char * , int);
void print_tcp_packet(const u_char *  , int );
void print_udp_packet(const u_char * , int);
void print_icmp_packet(const u_char * , int );
void PrintData (const u_char * , int);

FILE *logfile;

int main()
{
	pcap_if_t *alldevsp , *device;
	pcap_t *handle;
	logfile=fopen("log.txt","w");
	char errbuf[100] , *devname , devs[100][100];
	int count = 1 , n;
	
	printf("Finding available devices ... ");
	if( pcap_findalldevs( &alldevsp , errbuf) )
	{
		printf("Error finding devices : %s" , errbuf);
		exit(1);
	}
	
	//Print the available devices
	printf("\nAvailable Devices are :\n");
	for(device = alldevsp ; device != NULL ; device = device->next)
	{
		printf("%d. %s - %s - %d \n" , count , device->name , device->description, device->flags);
		if(device->name != NULL)
		{
			strcpy(devs[count] , device->name);  //get interface name 
		}
		count++;
	}

	//Ask user which device to sniff
	printf("Enter the number of the device you want to sniff : ");
	scanf("%d", &n);
    devname = devs[n];

    //Open the device for sniffing
	handle = pcap_open_live(devname, 65536, 1, 0, errbuf);

    //Create filter expression
	struct bpf_program fcode;
    const char *filter = "icmp";
    //Compile filter expression
    pcap_compile(handle, &fcode, filter, 1, PCAP_NETMASK_UNKNOWN);
    //Set filter
    pcap_setfilter(handle, &fcode);
    //Start packet sniffer
	pcap_loop(handle, -1, process_packet, NULL);
	return 0;	
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	int size = header->len;
    //print byte value
	printf("\nPacket Strat\n");
	for(int i = 0 ; i < header->caplen ; i++) {
        printf("%02x ", buffer[i]);
		if(i%16==0 && i!=0)
		printf("\n");
    }
	printf("\nPacket End\n");
}
