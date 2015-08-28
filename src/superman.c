/*
 * Playing with probes from these repos
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
#include <net/ethernet.h>
#include "radiotap.h"

typedef uint8_t mac_t[6];

static uint8_t verbose = 0;
static uint8_t timestamp[8] = {0xFF};

/* static mac_t ap_base_mac = {0x02, 0xDE, 0xAD, 0xBE, 0xEF, 0x42}; */
/* static mac_t brd_mac     = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; */
/* static mac_t dest_mac    = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; */

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

void get_essid(char *essid, const uint8_t *p, const size_t max_psize) {
  /* const uint8_t *end = p+max_psize; */
  /* p += 4; //+6+6+6+2; */
  /* while (p < end) { */
  /*   if (*p == 0x00) { */
  /*     /1* if (p[1] == 0) { *1/ */

  /*     /1* } else { *1/ */
  /*       /1* strncpy(essid, &p[2], p[1]); *1/ */
  /*     /1* } *1/ */
  /*     essid[p[1]] = '\0'; */
  /*     break; */
  /*   } else { */
  /*     p += 1+p[1]; */
  /*   } */
  /* } */
}

void pcap_callback(u_char *bp, const struct pcap_pkthdr *header, const uint8_t *packet) {

  char essid[0xFF];
  struct ieee80211_radiotap_header *rh =(struct ieee80211_radiotap_header *)packet;
  uint16_t rt_length = (packet[2] | (uint16_t)packet[3]>>8);
  const uint8_t *p = &packet[rt_length];
  client_mac(&p[4]);
  printf("len: %i\n", rt_length);
  /* printf("lll: %i\n", rh->it_len); */

  get_essid(essid, p, header->caplen);
  printf("ssss: %s\n", essid);

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

  while ((c = getopt(argc, argv, "i:v")) != -1) {
    switch(c) {
      case 'i':
        printf("Listen on interface %s\n", optarg);
        if_name = optarg;
        break;
      case 'v':
        verbose = 1;
        break;
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
