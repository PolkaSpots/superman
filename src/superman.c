/*
 * Playing with probes from this repo
 * https://github.com/wertarbyte/blighthouse
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

/* #include <signal.h> */
/* #include <netinet/ip.h> */
/* #include <sys/time.h> */
/* #include <net/ethernet.h> */
/* #include <pthread.h> */

typedef uint8_t mac_t[6];

static uint8_t verbose = 0;
static uint8_t timestamp[8] = {0xFF};

static mac_t ap_base_mac = {0x02, 0xDE, 0xAD, 0xBE, 0xEF, 0x42};
static mac_t brd_mac     = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static mac_t dest_mac    = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

struct network_t {
  char ssid[33]; /* ESSID name (0-terminated string) */
  mac_t mac;
  mac_t dst;
  uint16_t seq;
  uint8_t channel;
  uint8_t flags;
  struct network_t *next;
};

void client_mac(const mac_t m) {
  /* printf("%s ", m); */
  printf("%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", m[0], m[1], m[2], m[3], m[4], m[5]);
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
  const uint8_t *end = p+max_psize;
  p += 4+6+6+6+2;
  while (p < end) {
    if (*p == 0x00) {
      if (p[1] == 0) {

      } else {
        strncpy(essid, &p[2], p[1]);
      }
      essid[p[1]] = '\0';
      break;
    } else {
      p += 1+p[1];
    }
  }
}

void pcap_callback(u_char *bp, const struct pcap_pkthdr *header, const uint8_t *packet) {

  char essid[0xFF];

  /* u_int8_t eth_a[ETH_ALEN]; */
  /* u_int8_t eth_b[ETH_ALEN]; */

  /* struct ether_header ehdr; */
  /* memcpy( &ehdr, packet, sizeof( struct ether_header )); */

  /* /1*  Only transmit source address is 0xfe(lan MAC last bytes) *1/ */

  /* int i; */

  /* printf("eth0 src: "); */
  /* for (i=1; i <= ETH_ALEN; i++) */
  /*   printf("%02x ", ehdr.ether_shost[ETH_ALEN-i]); */
  /* printf(" dst: "); */
  /* for (i=1; i <= ETH_ALEN; i++) */
  /*   printf("%02x ", ehdr.ether_dhost[ETH_ALEN-i] ); */
  
  /* printf("%02x ", ehdr.ether_dhost[4] ); */
  /* printf("\n"); */

  uint16_t rt_length = (packet[2] | (uint16_t)packet[3]>>8);
  const uint8_t *p = &packet[rt_length];
  /* printf("packet %i", packet[2]); */
  /* printf("packet %i", &packet[3]); */

  /* char essid[0xFF]; */
  /* printf("packet %s", &packet); */
  get_essid(essid, p, header->caplen);
  printf("Incoming probe from ");
  client_mac(&p[4]);
  printf(" going to ");
  client_mac(&p[5]);
  printf(" ssid %s", essid);
  printf("\n");
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
