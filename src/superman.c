/*
 *  Packet Filter, Mainly For OpenWrt
 *  Copyright (C) Cucumber Tony Limited
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL. *  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so. *  If you
 *  do not wish to do so, delete this exception statement from your
 *  version. *  If you delete this exception statement from all source
 *  files in the program, then also delete it here.

 *  With thanks to the follow people for helping us on our way:
 *  https://github.com/wertarbyte/blighthouse
 *  https://github.com/Joel-Schofield/RSSI-Sniffer
 *  https://github.com/aircrack-ng/aircrack-ng.git
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
#include "radiotap_iter.h"

#define MESSAGE_BUFF_LEN                        200

static char *ap_mac = NULL;
static uint8_t verbose = 0;

struct Ap {
    char *ap_mac;
    /* int lat; */
    /* int lat; */
};

static const struct radiotap_align_size align_size_000000_00[] = {
  [0] = { .align = 1, .size = 4, },
  [52] = { .align = 1, .size = 4, },
};

static const struct ieee80211_radiotap_namespace vns_array[] = {
  {
    .oui = 0x000000,
    .subns = 0,
    .n_bits = sizeof(align_size_000000_00),
    .align_size = align_size_000000_00,
  },
};

static const struct ieee80211_radiotap_vendor_namespaces vns = {
  .ns = vns_array,
  .n_ns = sizeof(vns_array)/sizeof(vns_array[0]),
};


typedef struct {
  u_int8_t        it_version;
  u_int8_t        it_pad;
  u_int16_t       it_len;
  u_int32_t       it_present;

  u_int32_t       pad;
  u_int8_t        flags;
  u_int8_t        rate;
  int8_t          ant_sig;
  int8_t          ant_noise;
  int8_t          lock_quality;
  u_int8_t        ant;

} __attribute__((__packed__)) ieee80211_radiotap;

typedef struct {
  unsigned short                  fc;             /* frame control */
  unsigned short                  durid;          /* duration/ID */
  u_char  a1[6];          /* address 1 */
  u_char  a2[6];          /* address 2 */
  u_char  a3[6];          /* address 3 */
  unsigned short                  seq;            /* sequence control */
  u_char  a4[6];          /* address 4 */
} __attribute__((__packed__)) dot11_header;

void print_mac(FILE * stream,u_char * mac);

void pcap_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

  char messageBuff[MESSAGE_BUFF_LEN];

  int err;
  int radiotap_header_len;
  int8_t rssi;
  struct ieee80211_radiotap_iterator iter;

  err = ieee80211_radiotap_iterator_init(&iter, (void*)packet, 25, &vns);

  radiotap_header_len = iter._max_length; 

  if (verbose) {
    printf("header length: %d\n", radiotap_header_len);
  };

  if (verbose) {
    while (!(err = ieee80211_radiotap_iterator_next(&iter))) {
      if (iter.this_arg_index == IEEE80211_RADIOTAP_DBM_ANTSIGNAL) {
        rssi = (int8_t)iter.this_arg[0];
        printf("antsignal is: %d\n", rssi);
      }
    }
  };

  dot11_header * dot_head = (dot11_header*) (packet + radiotap_header_len * sizeof(char) );
  if (verbose) {
    printf("dest: "); print_mac(stdout, dot_head->a1); printf("\n");
    printf("src:"); print_mac(stdout, dot_head->a2); printf("\n");
    printf("rssi:", rssi); printf("\n");
  };

  sprintf(messageBuff, "{\"ap_mac\":\"%s\",\"rssi\":%d,\"macSrc\":\"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\"}", 
      ap_mac,
      rssi, 
      dot_head->a2[0],
      dot_head->a2[1],
      dot_head->a2[2],
      dot_head->a2[3],
      dot_head->a2[4],
      dot_head->a2[5]
      );

  if (verbose) {
    printf("{\"ap_mac\":\"%s\",\"rssi\":%d,\"macSrc\":\"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\"}\n", 
        ap_mac,
        rssi, 
        dot_head->a2[0],
        dot_head->a2[1],
        dot_head->a2[2],
        dot_head->a2[3],
        dot_head->a2[4],
        dot_head->a2[5]
        );
  };

}

void print_mac(FILE * stream,u_char * mac) {
  for (int i=0; i < 6; i++) {
    fprintf(stream, "%.2x", mac[i]);
  }
}

int main(int argc, char *argv[]) {

  char pcap_errbuf[PCAP_ERRBUF_SIZE];
  pcap_errbuf[0] = '\0';

  char *if_name = NULL;
  int  c;
  opterr = 0;

  while ((c = getopt(argc, argv, "i:m:v")) != -1) {
    switch(c) {
      case 'i':
        printf("Listen on interface %s\n", optarg);
        if_name = optarg;
        break;
        case 'm':
          ap_mac = optarg;
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

  int link_layer_type = pcap_datalink(pcap);

  if (link_layer_type != DLT_IEEE802_11_RADIO) {
    // Not 80211 so we're probably testing something on a lappy //
    const char *lln_pre = pcap_datalink_val_to_name(link_layer_type);
    const char *lln_req = pcap_datalink_val_to_name(DLT_IEEE802_11_RADIO);
    fprintf(stderr, "Not using the Wi-Fi interface, are you testing something?\n");
    while (1) {

    }
    /* pcap_close(pcap); */
    /* exit(1); */
  } else {

    struct bpf_program filter_probe_req;
    struct bpf_program filter_probe_resp;
    pcap_compile(pcap, &filter_probe_req, "type mgt subtype probe-req", 1, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(pcap, &filter_probe_req);

    pcap_compile(pcap, &filter_probe_resp, "type mgt subtype probe-resp", 1, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(pcap, &filter_probe_resp);

    while (1) {
      pcap_loop(pcap, -1, &pcap_callback, "beacon");
    }
  }

  pcap_close(pcap);
  return 0;

}
