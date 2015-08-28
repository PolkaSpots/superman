/*
 * Playing with probes from this repo
 * https://github.com/wertarbyte/blighthouse
 * https://github.com/Joel-Schofield/RSSI-Sniffer
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
/* #include <net/ethernet.h> */

typedef uint8_t mac_t[6];

#define MESSAGE_BUFF_LEN                        200
#define NODE_ID_LEN                             200

void client_mac(const mac_t m) {
  /* printf("%s ", m); */
  printf("%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX\n", m[0], m[1], m[2], m[3], m[4], m[5]);
  /* printf("%02X:%02X:%02X:%02X:%02X:%02X\n", m[5], m[4], m[3], m[2], m[1], m[0]); */
}

static char *append_to_buf(char *buf, char *data, int size) {
  memcpy(buf, data, size);
  return buf+size;
}

static char *append_str(char *buf, char *data) {
  int size = strlen(data);
  return append_to_buf(buf, data, size);
}

struct ieee80211_radiotap_header {
  u_int8_t it_pad;
  u_int32_t it_present;
  u_int16_t it_len;       
};

//ethernet packet header.
typedef struct {
  unsigned short                  fc;             /* frame control */
  unsigned short                  durid;          /* duration/ID */
  u_char  a1[6];          /* address 1 */
  u_char  a2[6];          /* address 2 */
  u_char  a3[6];          /* address 3 */
  unsigned short                  seq;            /* sequence control */
  u_char  a4[6];          /* address 4 */
} __attribute__((__packed__)) dot11_header;

volatile u_int8_t wifi_channel;
char node_id[NODE_ID_LEN];

void print_mac(FILE * stream,u_char * mac);

void pcap_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

  //quickly grab the wifi channel incase it changes while processing the packet.
  u_int8_t packet_channel = wifi_channel;

  char messageBuff[MESSAGE_BUFF_LEN]; //buffer for storing a message to be sent.

  int err;
  int radiotap_header_len;
  int8_t rssi;
  /* struct ieee80211_radiotap_iterator iter; */

  /* err = ieee80211_radiotap_iterator_init(&iter, (void*)packet, 25, &vns); */
  /* if (err == 0) */ 
  /*   fprintf(stdout, "all good!\n"); */
  /* else */ 
  /*   fprintf(stdout, "all bad! %d\n", err); */

  //extract the length of the header.
  /* radiotap_header_len = iter._max_length; */ 

  //sanity printf of header length.
  printf("header length: %d\n", radiotap_header_len);

  //loop through the packet, looking for the desired data (rssi)
  /* while (!(err = ieee80211_radiotap_iterator_next(&iter))) { */

  /*   if (iter.this_arg_index == IEEE80211_RADIOTAP_DBM_ANTSIGNAL) { */
  /*     rssi = (int8_t)iter.this_arg[0]; */
  /*     printf("antsignal is: %d\n", rssi); */
  /*   } */
  /* } */

  //cast received packet into ethernet packet header. the size of the radiotap header can change, hence cannot
  //be cast statically. 
  dot11_header * dot_head = (dot11_header*) (packet + radiotap_header_len * sizeof(char) );
  printf("dest: "); print_mac(stdout, dot_head->a1); printf("\n");
  printf("src:"); print_mac(stdout, dot_head->a2); printf("\n");

  /*
     for (int i=0; i < 64; i++) {
     if (i%4 == 0 && i != 0)
     fprintf(stdout, "\n");
     fprintf(stdout, "%0.2x", packet[i]);
     }
     fprintf(stdout, "\n");
     */


  sprintf(messageBuff, "{\"node_id\":\"%s\",\"channel\":%d,\"rssi\":%d,\"macSrc\":\"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\"}", 
      node_id,
      packet_channel,
      rssi, 
      dot_head->a2[0],
      dot_head->a2[1],
      dot_head->a2[2],
      dot_head->a2[3],
      dot_head->a2[4],
      dot_head->a2[5]
      );

};

void print_mac(FILE * stream,u_char * mac) {
  /* for (int i=0; i < 6; i++) { */
  /*   fprintf(stream, "%.2x", mac[i]); */
  /* } */
  int i = 0;
  for (i=1; i <= 6; i++)
    printf("%.2x", mac[i]);
}

/* void print_mac(FILE * stream,u_char * mac) { */
/*         for (int i=0; i < 6; i++) { */
/*                 fprintf(stream, "%.2x", mac[i]); */
/*         } */
/* } */


void xxxpcap_callback(u_char *bp, const struct pcap_pkthdr *header, const uint8_t *packet) {

  /* char essid[0xFF]; */
  /* struct ieee80211_radiotap_header *rh =(struct ieee80211_radiotap_header *)packet; */
  /* uint16_t rt_length = (packet[2] | (uint16_t)packet[3]>>8); */
  /* const uint8_t *p = &packet[rt_length]; */
  /* client_mac(&p[4]); */
  /* printf("len: %i\n", rt_length); */
  /* printf("lll: %i\n", rh->it_len); */

  /* get_essid(essid, p, header->caplen); */
  /* printf("ssss: %s\n", essid); */

};

void xxx(u_char *bp, const struct pcap_pkthdr *header, const uint8_t *packet) {

  /* char essid[0xFF]; */

  /* struct ieee80211_radiotap_header *rh =(struct ieee80211_radiotap_header *)packet; */

  /* printf("Received Packet Size: %d and fields: % \n", header->len, rh->it_present); */

  /* Oh, and if you want to be really careful, make sure, when you're looking at the radiotap and 802.11 header, that you haven't gone past pkthdr->caplen. */

  /* u_int8_t eth_a[ETH_ALEN]; */
  /* u_int8_t eth_b[ETH_ALEN]; */

  /* struct ether_header ehdr; */
  /* memcpy( &ehdr, packet, sizeof( struct ether_header )); */

  /* /1* /2*  Only transmit source address is 0xfe(lan MAC last bytes) *2/ *1/ */

  /* int i; */

  /* printf("eth0 src: "); */
  /* for (i=1; i <= ETH_ALEN; i++) */
  /*   printf("%02X:", ehdr.ether_shost[ETH_ALEN-i]); */
  /* printf(" dst: "); */
  /* for (i=1; i <= ETH_ALEN; i++) */
  /*   printf("%02x ", ehdr.ether_dhost[ETH_ALEN-i] ); */

  /* client_mac(ehdr.ether_shost); */
  /* client_mac(ehdr.ether_dhost); */
  /* printf("%02x ", ehdr.ether_dhost[4] ); */
  /* printf("\n"); */

  uint16_t rt_length = (packet[2] | (uint16_t)packet[3]>>8);
  const uint8_t *p = &packet[rt_length];
  /* /1* printf("packet %i", packet[2]); *1/ */
  /* /1* printf("packet %i", &packet[3]); *1/ */

  /* /1* char essid[0xFF]; *1/ */
  /* printf("packet %i", header->caplen); */
  /* printf("packet %i", header->len); */
  /* get_essid(essid, p, header->caplen); */
  /* printf("Incoming probe from "); */
  client_mac(&p[4]);
  /* printf(" going to "); */
  /* client_mac(&p[5]); */
  /* printf(" ssid %s", essid); */
  /* printf( " asdfasdf %i ", rh); */
  /* printf("\n"); */
}

int main(int argc, char *argv[]) {

  char pcap_errbuf[PCAP_ERRBUF_SIZE];
  pcap_errbuf[0] = '\0';

  char *if_name = NULL;
  int  c;
  opterr = 0;

  while ((c = getopt(argc, argv, "i")) != -1) {
    switch(c) {
      case 'i':
        printf("Listen on interface %s\n", optarg);
        if_name = optarg;
        break;
      /* case 'v': */
      /*   verbose = 1; */
      /*   break; */
      default:
        abort();
    }
  }

  pcap_t *pcap = pcap_open_live(if_name, 1024, 0, 1, pcap_errbuf);
  if (!pcap) {
    printf("%s\n", pcap_errbuf);
    exit(1);
  }

  printf("Listening...\n");
  struct bpf_program filter_probe_req;
  struct bpf_program filter_probe_resp;
  pcap_compile(pcap, &filter_probe_req, "type mgt subtype probe-req", 1, PCAP_NETMASK_UNKNOWN);
  pcap_setfilter(pcap, &filter_probe_req);

  pcap_compile(pcap, &filter_probe_resp, "type mgt subtype probe-resp", 1, PCAP_NETMASK_UNKNOWN);
  pcap_setfilter(pcap, &filter_probe_resp);

  int link_layer_type = pcap_datalink(pcap);

  if (link_layer_type != DLT_IEEE802_11_RADIO) {
    const char *lln_pre = pcap_datalink_val_to_name(link_layer_type);
    const char *lln_req = pcap_datalink_val_to_name(DLT_IEEE802_11_RADIO);
    fprintf(stderr, "Unsupported interface (%s), '%s' is required\n", lln_pre, lln_req);
    pcap_close(pcap);
    exit(1);
  }

  while (1) {
    pcap_dispatch(pcap, -1, &pcap_callback, "beacon");
  }
  pcap_close(pcap);
  return 0;

}
