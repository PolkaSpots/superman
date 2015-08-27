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
/* #include <ctype.h> */
/* #include <time.h> */

/* #include "types.h" */
/* #include "network.h" */
/* #include "packet.h" */

#define TYPES_H_
#define NETWORK_H_
#define NETWORK_FLAG_WPA  (1<<0)
#define NETWORK_FLAG_TIME (1<<1)

typedef uint8_t mac_t[6];
/* #include <stdio.h> */
/* #include <stdlib.h> */
/* #include <stdint.h> */
/* #include <unistd.h> */
/* #include <string.h> */

/* #include "network.h" */

struct network_t {
  char ssid[33]; /* ESSID name (0-terminated string) */
  mac_t mac;
  mac_t dst;
  uint16_t seq;
  uint8_t channel;
  uint8_t flags;
  struct network_t *next;
};

struct network_t *network_add(struct network_t **list, char *ssid, mac_t m, mac_t d, uint8_t flags);

int network_count(struct network_t **list);

struct network_t *network_find(struct network_t **list, char *ssid);

static uint8_t verbose = 0;

static struct network_t *network_list = NULL;

void print_mac(const mac_t m) {
  printf("%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", m[0], m[1], m[2], m[3], m[4], m[5]);
}

/* struct network_t *network_add(struct network_t **list, char *ssid, mac_t m, mac_t d, uint8_t flags) { */
/*   while (*list) { */
/*     list = &(*list)->next; */
/*   } */
/*   *list = malloc(sizeof(**list)); */
/*   strncpy((*list)->ssid, ssid, sizeof((*list)->ssid)); */
/*   (*list)->ssid[32] = '\0'; */
/*   memcpy((*list)->mac, m, sizeof(mac_t)); */
/*   memcpy((*list)->dst, d, sizeof(mac_t)); */
/*   (*list)->seq = 0; */
/*   (*list)->flags = flags; */
/*   (*list)->next = NULL; */
/* } */

int network_count(struct network_t **list) {
  int i = 0;
  while (*list) {
    list = &(*list)->next;
    i++;
  }
  return i;
}

struct network_t *network_find(struct network_t **list, char *ssid) {
  while (*list) {
    if (strcmp(ssid, (*list)->ssid) == 0) {
      return *list;
    }
    list = &(*list)->next;
  }
  return NULL;
}

void get_essid(char *essid, const uint8_t *p, const size_t max_psize) {
  /* const uint8_t *end = p+max_psize; */
  /* p += 4+6+6+6+2; */
  /* while (p < end) { */
  /*   if (*p == 0x00) { */
  /*     if (p[1] == 0) { */
  /*       /1*  nothing to do *1/ */
  /*     } else { */
  /*       strncpy(essid, &p[2], p[1]); */
  /*     } */
  /*     essid[p[1]] = '\0'; */
  /*     break; */
  /*   } else { */
  /*     p += 1+p[1]; */
  /*   } */
  /* } */
}

void process_probe(u_char *user, const struct pcap_pkthdr *h, const uint8_t *b) {
  /*  where does the wifi header start? */
  uint16_t rt_length = (b[2] | (uint16_t)b[3]>>8);
  const uint8_t *p = &b[rt_length];
  char essid[0xFF];
  get_essid(essid, p, h->caplen);
  if (verbose) {
    printf("Incoming request\n");
    printf("DST: "); print_mac(&p[4]); printf("\n");
    printf("SRC: "); print_mac(&p[4+6]); printf("\n");
    printf("BSS: "); print_mac(&p[4+6+6]); printf("\n");
    printf("SSID <%s>\n", essid);
  }
  struct network_t *n = network_find(&network_list, essid);
  if (n) {
    printf("Incoming probe from ");
    print_mac(&p[4+6]);
    printf(" for ssid <%s>\n", essid);
  }
}

int main(int argc, char *argv[]) {

  char pcap_errbuf[PCAP_ERRBUF_SIZE];
  pcap_errbuf[0] = '\0';

  char *if_name = NULL;
  uint8_t use_wpa = 0;
  uint8_t time_ssid = 0;
  uint8_t listen = 0;
  int channel = 1;


  int  c;
  opterr = 0;

  while ((c = getopt(argc, argv, "i")) != -1) {
    switch(c) {
      case 'i':
        if_name = "mon0";
        break;
      default:
        abort();
    }
  }

  printf("%s\n", if_name);

  pcap_t *pcap = pcap_open_live(if_name, 1024, 0, 1, pcap_errbuf);
  if (!pcap) {
    printf("%s\n", pcap_errbuf);
    exit(1);
  }
  if (listen) {
    struct bpf_program filter_probe_req;
    pcap_compile(pcap, &filter_probe_req, "type mgt subtype probe-req", 1, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(pcap, &filter_probe_req);
  }

  int link_layer_type = pcap_datalink(pcap);
  if (link_layer_type != DLT_IEEE802_11_RADIO) {
    const char *lln_pre = pcap_datalink_val_to_name(link_layer_type);
    const char *lln_req = pcap_datalink_val_to_name(DLT_IEEE802_11_RADIO);
    fprintf(stderr, "Unsupported link layer format (%s), '%s' is required\n", lln_pre, lln_req);
    pcap_close(pcap);
    exit(1);
  }

  char beacon[1024];
  struct network_t *nw = network_list;

  while (1) {
    if (nw->flags & NETWORK_FLAG_TIME) {
      /* t = time(NULL); */
      /* tmp = localtime(&t); */
      /* if (!tmp) { */
      /*   perror("localtime"); */
      /*   exit(1); */
      /* } */
      /* strftime(nw->ssid, 32, "%Y-%m-%d %H:%M", tmp); */
    }
    /* int buffersize = build_beacon(beacon, nw); */
    /* int s = pcap_inject(pcap, beacon, buffersize); */

    /* if (verbose) { */
    /*   printf("sending beacon '%s'", nw->ssid); */
    /*   printf(" (AP: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx)", nw->mac[0], nw->mac[1], nw->mac[2], nw->mac[3], nw->mac[4], nw->mac[5]); */
    /*   printf("\n"); */
    /* } */

    /* usleep(100000/network_count(&network_list)); */
    /* nw = nw->next; */
    /* if (nw == NULL) nw = network_list; */

    /* if (listen) { */
    /*   pcap_dispatch(pcap, -1, &process_probe, "beacon"); */

    pcap_close(pcap);
    return 0;
  }
  }
