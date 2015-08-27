#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#define SNAP_LEN 1518

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

  static int count = 1;                   /* packet counter */

  /* declare pointers to packet headers */
  const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
  const struct sniff_ip *ip;              /* The IP header */
  const struct sniff_tcp *tcp;            /* The TCP header */
  const char *payload;                    /* Packet payload */

  int size_ip;
  int size_tcp;
  int size_payload;

  printf("\nPacket number %d:\n", count);
  /* count++; */

  /* /1* define ethernet header *1/ */
  /* ethernet = (struct sniff_ethernet*)(packet); */

  /* /1* define/compute ip header offset *1/ */
  /* ip = (struct sniff_ip*)(packet + SIZE_ETHERNET); */
  /* size_ip = IP_HL(ip)*4; */
  /* if (size_ip < 20) { */
  /*   printf("   * Invalid IP header length: %u bytes\n", size_ip); */
  /*   return; */
  /* } */

  /* /1* print source and destination IP addresses *1/ */
  /* printf("       From: %s\n", inet_ntoa(ip->ip_src)); */
  /* printf("         To: %s\n", inet_ntoa(ip->ip_dst)); */

  /* /1* determine protocol *1/ */	
  /* switch(ip->ip_p) { */
  /*   case IPPROTO_TCP: */
  /*     printf("   Protocol: TCP\n"); */
  /*     break; */
  /*   case IPPROTO_UDP: */
  /*     printf("   Protocol: UDP\n"); */
  /*     return; */
  /*   case IPPROTO_ICMP: */
  /*     printf("   Protocol: ICMP\n"); */
  /*     return; */
  /*   case IPPROTO_IP: */
  /*     printf("   Protocol: IP\n"); */
  /*     return; */
  /*   default: */
  /*     printf("   Protocol: unknown\n"); */
  /*     return; */
  /* } */

  /* /1* define/compute tcp header offset *1/ */
  /* tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip); */
  /* size_tcp = TH_OFF(tcp)*4; */
  /* if (size_tcp < 20) { */
  /*   printf("   * Invalid TCP header length: %u bytes\n", size_tcp); */
  /*   return; */
  /* } */

  /* printf("   Src port: %d\n", ntohs(tcp->th_sport)); */
  /* printf("   Dst port: %d\n", ntohs(tcp->th_dport)); */

  /* /1* define/compute tcp payload (segment) offset *1/ */
  /* payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp); */

  /* /1* compute tcp payload (segment) size *1/ */
  /* size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp); */

  /*  * Print payload data; it might be binary, so don't just */
  /*  * treat it as a string. */
  /*  *1/ */
  /* if (size_payload > 0) { */
  /*   printf("   Payload (%d bytes):\n", size_payload); */
  /*   print_payload(payload, size_payload); */
  /* } */

  return;
}

int main(int argc, char *argv[])
{
  char *dev = argv[1];
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  char filter_exp[] = "ip";
  struct bpf_program fp;
  bpf_u_int32 net;
  int num_packets = 10;

  handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    exit(EXIT_FAILURE);
  }

  if (pcap_datalink(handle) != DLT_EN10MB) {
    fprintf(stderr, "%s is not an Ethernet\n", dev);
    exit(EXIT_FAILURE);
  }

  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n",
        filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n",
        filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  pcap_loop(handle, num_packets, got_packet, NULL);

  pcap_freecode(&fp);
  pcap_close(handle);

  printf("\nCapture complete.\n");
}
