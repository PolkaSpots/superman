#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#define SNAP_LEN 1518

int main(int argc, char *argv[])
{
  char *dev = argv[1];
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  char filter_exp[] = "ip";
  struct bpf_program fp;
  bpf_u_int32 net;

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

}
