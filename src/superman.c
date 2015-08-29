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
 *  http://www.tcpdump.org/sniffex.c
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
#include <arpa/inet.h>
#include <json/json.h>
#include <time.h>

#define MESSAGE_BUFF_LEN  200

// Only for the ethernet tests //

#define SIZE_ETHERNET     14
#define SNAP_LEN          1518
#define ETHER_ADDR_LEN6   6

struct sniff_ethernet {
  u_char  ether_dhost[ETHER_ADDR_LEN];    /*  destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN];    /*  source host address */
  u_short ether_type;                     /*  IP? ARP? RARP? etc */
};

struct sniff_ip {
  u_char  ip_vhl;                 /*  version << 4 | header length >> 2 */
  u_char  ip_tos;                 /*  type of service */
  u_short ip_len;                 /*  total length */
  u_short ip_id;                  /*  identification */
  u_short ip_off;                 /*  fragment offset field */
#define IP_RF 0x8000            /*  reserved fragment flag */
#define IP_DF 0x4000            /*  dont fragment flag */
#define IP_MF 0x2000            /*  more fragments flag */
#define IP_OFFMASK 0x1fff       /*  mask for fragmenting bits */
  u_char  ip_ttl;                 /*  time to live */
  u_char  ip_p;                   /*  protocol */
  u_short ip_sum;                 /*  checksum */
  struct  in_addr ip_src,ip_dst;  /*  source and dest address */
};

#define IP_HL(ip)         (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)          (((ip)->ip_vhl) >> 4)

/*  TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
  u_short th_sport;               /*  source port */
  u_short th_dport;               /*  destination port */
  tcp_seq th_seq;                 /*  sequence number */
  tcp_seq th_ack;                 /*  acknowledgement number */
  u_char  th_offx2;               /*  data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
  u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  u_short th_win;                 /*  window */
  u_short th_sum;                 /*  checksum */
  u_short th_urp;                 /*  urgent pointer */
};

void ethernet_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

// End only for the ethernet tests //

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
      dot_head->a4[0],
      dot_head->a4[1],
      dot_head->a4[2],
      dot_head->a4[3],
      dot_head->a4[4],
      dot_head->a4[5]
      );

  if (verbose) {
    printf("{\"ap_mac\":\"%s\",\"rssi\":%d,\"macSrc\":\"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\"}\n", 
        ap_mac,
        rssi, 
        dot_head->a4[0],
        dot_head->a4[1],
        dot_head->a4[2],
        dot_head->a4[3],
        dot_head->a4[4],
        dot_head->a4[5]
        );
  };

}

void print_mac(FILE * stream,u_char * mac) {
  for (int i=0; i < 6; i++) {
    fprintf(stream, "%.2x", mac[i]);
  }
}

int array_contains(char *array, char *ip ) {
  if ( strchr(array, *ip) ) 
    return 1;
}

void add_to_macs(char *ip, json_object *array, json_object *parent, int count) {

};


/* struct json_object *obj1, *obj2, *res, *sub_obj1, *sub_obj2, *tmp; */

/* const res = json_object_new_array(); */ 
/* obj1 = json_object_new_object(); */
/* obj2 = json_object_new_object(); */

void ethernet_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

  static int count = 1;               
  time_t t0 = time(0);
  struct json_object *obj1, *obj2, *array, *tmp1, *tmp2;

  char *val_type_str, *str;
  int val_type, i;
  val_type = json_object_get_type(array);

  switch (val_type) {
    case json_type_null:
      val_type_str = "val is NULL";
      break;

    case json_type_boolean:
      val_type_str = "val is a boolean";
      break;

    case json_type_double:
      val_type_str = "val is a double";
      break;

    case json_type_int:
      val_type_str = "val is an integer";
      break;

    case json_type_string:
      /* val_type_str = "val is a string"; */
      /* str = (char *) json_object_get_string(val); */
      break;

    case json_type_object:
      val_type_str = "val is an object";
      break;

    case json_type_array:
      val_type_str = "val is an array";
      break;
    default:
      printf("aaaaaaaaaaaaaa");
      array = json_object_new_array();
      /* obj1 = json_object_new_object(); */
  }

  obj1 = json_object_new_object();

  const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
  const struct sniff_ip *ip;              /* The IP header */
  const struct sniff_tcp *tcp;            /* The TCP header */
  const char *payload;                    /* Packet payload */

  int size_ip;
  int size_tcp;
  int size_payload;
  char *src_ip;
  char *dst_ip;

  /* printf("\nPacket number %d:\n", count); */
  count++;

  ethernet = (struct sniff_ethernet*)(packet);

  ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
  size_ip = IP_HL(ip)*4;
  if (size_ip < 20) {
    printf("   * Invalid IP header length: %u bytes\n", size_ip);
    return;
  }

  char buf[MESSAGE_BUFF_LEN];

  src_ip = inet_ntoa(ip->ip_src);
  dst_ip = inet_ntoa(ip->ip_dst);

  if (!array_contains(buf, src_ip)) {

    obj2 = json_object_new_object();
    sprintf(buf, src_ip);
    /*   *//* add_to_macs(src_ip, res, obj1, count); */
    json_object *jsrc = json_object_new_string(dst_ip);
    json_object *timestamp = json_object_new_int(t0);
    json_object_object_add(obj2,"ip", jsrc);
    json_object_object_add(obj2,"first_seen", timestamp);
    json_object_object_add(obj2,"last_seen", timestamp);
    json_object_array_add(array,obj2);

  } else {

    /* const char *original_key = NULL; */
    int orig_count = 0;

    int arraylen, i;
    arraylen = json_object_array_length(array);
    for (i = 0; i < arraylen; i++) {
      tmp1 = json_object_array_get_idx(array, i);
      json_object_object_get_ex(tmp1, "ip", &tmp2);

      int result = strcmp(json_object_get_string(tmp2), dst_ip);

      if ( result == 0 ) {

        json_object_object_foreach(tmp1, key, val) {
          if (strcmp(key, "last_seen") != 0)
            continue;
          printf("replacing value for key [%s]\n", key);
          /* original_key = key; */
          json_object_object_add(tmp1, key, json_object_new_int(t0));


          break;

        }

        /* json_object *timestamp = json_object_new_int(t0); */
        /* json_object_object_add(tmp1, "last_seen", timestamp); */
        /* Exit loop */
      }
    }
        
    
    json_object_put( array );

    /* json_object_object_foreach(array, key, val) { */
    /*   /1*   /2* printf("Key at index %d is [%s]\n", orig_count, key); *2/ *1/ */
    /* } */

  }


  if (count > 100) {
    /* printf ("The json object created: %s\n",json_object_to_json_string(array)); */
  };

  return;
}

struct node {
  int x;
  struct node *next;
};

int main(int argc, char *argv[]) {

  char pcap_errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "ip";
  bpf_u_int32 net;
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

  // Not 80211 so we're probably testing something //

  if (link_layer_type != DLT_IEEE802_11_RADIO) {
    fprintf(stderr, "Not using the Wi-Fi interface, are you testing something?\n");
    if (pcap_compile(pcap, &fp, filter_exp, 0, net) == -1) {
      fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(pcap));
      exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(pcap, &fp) == -1) {
      fprintf(stderr, "Couldn't install filter %s: %s\n",
          filter_exp, pcap_geterr(pcap));
      exit(EXIT_FAILURE);
    }
    /* while (1) { */
    pcap_loop(pcap, -1, ethernet_packet, NULL);
    /* } */
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

  printf("Done");
  pcap_close(pcap);
  return 0;

}

/* typedef struct tokens_ { */
/*   char *ID; */
/*   char *KEY; */
/*   char *TYPE; */
/*   json_object *parent; */
/* } tokens; */

/* const struct tokens_ TOKENS_DFLT = { */ 
/*   "a", "b", "c" */
/* }; */

