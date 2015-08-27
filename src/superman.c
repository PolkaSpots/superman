#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#define SNAP_LEN 1518

int main(int argc, char *argv[])
{
  char *dev = argv[1];
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];

  printf("Device: %s\n", dev);

  handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    exit(EXIT_FAILURE);
  }

}
