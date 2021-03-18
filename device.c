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

	char errbuf[100] , *devname , devs[100][100];
	int count = 1 , n;
	
	printf("Finding available devices ... ");
	if( pcap_findalldevs( &alldevsp , errbuf) )
	{
		printf("Error finding devices : %s" , errbuf);
		exit(1);
	}
	printf("Done");
	
	//Print the available devices
	printf("\nAvailable Devices are :\n");
	for(device = alldevsp ; device != NULL ; device = device->next)
	{
		printf("%d. %s - %s - %d \n" , count , device->name , device->description, device->flags);
		if(device->name != NULL)
		{
			strcpy(devs[count] , device->name);
		}
		count++;
	}
	logfile=fopen("log.txt","w+");
	scanf("%d", &n);
	handle = pcap_open_live(devname, 65536, 1, 0, errbuf);
	pcap_loop(handle, -1, process_packet, NULL);
	return 0;	
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	int size = header->len;
	fprintf(logfile , "\nPacket Strat\n");
	PrintData(buffer,size);
	fprintf(logfile , "\nPacket End\n");
}

void PrintData (const u_char * data , int Size)
{
	int i , j;
	for(i=0 ; i < Size ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			fprintf(logfile , "         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet
				
				else fprintf(logfile , "."); //otherwise print a dot
			}
			fprintf(logfile , "\n");
		} 
		
		if(i%16==0) fprintf(logfile , "   ");
			fprintf(logfile , " %02X",(unsigned int)data[i]);
				
		if( i==Size-1)  //print the last spaces
		{
			for(j=0;j<15-i%16;j++) 
			{
			  fprintf(logfile , "   "); //extra spaces
			}
			
			fprintf(logfile , "         ");
			
			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) 
				{
				  fprintf(logfile , "%c",(unsigned char)data[j]);
				}
				else 
				{
				  fprintf(logfile , ".");
				}
			}
			
			fprintf(logfile ,  "\n" );
		}
	}
}