#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <linux/tcp.h>

#define ETHER_ADDR_LEN 6

struct ipheader {
  unsigned char iph_ihl:4, // IP header length 
                iph_ver:4; // IP version
  unsigned char iph_tos;   // type of service
  unsigned short int iph_len; // IP packet length ( data + header )
  unsigned short int iph_ident; // identifier
  unsigned short int iph_flag:3, // fragmentation flag
                     iph_offset: 13; // flag offset
  unsigned char iph_ttl; // tome to live
  unsigned char iph_protocol; // protocol type
  unsigned short int iph_chksum; // IP datagram checksum
  struct in_addr iph_sourceip; // source IP address
  struct in_addr iph_destip; // destination IP address
};

struct ethheader {
  u_char ether_dhost[ETHER_ADDR_LEN]; // destination host address
  u_char ether_shost[ETHER_ADDR_LEN]; // source host address
  u_short ether_type; // IP? ARP? RARP? etc
};

void got_packet(u_char *args, const struct pcap_pkthdr * header, const u_char *packet)
{
  struct ethheader *eth = (struct ethheader*) packet;

  if(ntohs(eth->ether_type) == 0x0800) { // 0x0800 = IP TYPE
    struct ipheader *ip = (struct ipheader*) (packet + sizeof(struct ethheader));
    struct tcphdr *tcp  = (struct tcphdr*) ((u_char*) ip + sizeof(struct ipheader));

    unsigned short pktlen = ntohs(ip->iph_len);

    printf("\t FROM: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("\t TO: %s\n", inet_ntoa(ip->iph_destip));

    switch(ip->iph_protocol) {
      case IPPROTO_TCP:
        printf(" Protocol: TCP\n");
        u_char dataoffset = 4;

        if((pktlen - sizeof(struct ipheader)) > dataoffset) {
          u_char * data = (u_char*) tcp + dataoffset;
          printf(" Data: ");
          for(unsigned short s = 0; s < (ntohs(ip->iph_len) - (sizeof(struct ipheader) + dataoffset)); s++) {
            if(isprint(*data) != 0) {
              printf("%c", *data);
            } else {
              printf("\\%.3hho", *data);
            }
            data++;
          }
          printf("\n");
        }
        return;
      case IPPROTO_UDP:
        printf(" Protocol: UDP\n");
        return;
      case IPPROTO_ICMP:
        printf(" Protocol: ICMP\n");
        return;
      default:
        printf(" Protocol: other\n");
        return;
    }

  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  // char filter_exp[] = "ip proto icmp";
  //char filter_exp[] = "icmp and src host 10.0.2.15 and dst host 10.0.2.4";
  //char filter_exp[] = "tcp and portrange 10-100";
  char filter_exp[] = "tcp port telnet";
  bpf_u_int32 net;

  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

  pcap_compile(handle, &fp, filter_exp, 0, net);
  pcap_setfilter(handle, &fp);

  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);
  return 0;  
}
