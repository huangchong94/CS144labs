#include "ctcp_utils.h"

uint16_t cksum(const void *_data, uint16_t len) {
  const uint8_t *data = _data;
  uint32_t sum = 0;

  for (sum = 0; len >= 2; data += 2, len -=2) {
    sum += (data[0] << 8) | data[1];
  }
  if (len > 0) sum += data[0] << 8;

  while (sum > 0xffff) {
    sum = (sum >> 16) + (sum & 0xffff);
  }
  sum = htons(~sum);
  return sum ? sum : 0xffff;
}

long current_time() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

void print_hdr_ctcp(ctcp_segment_t *segment) {
  fprintf(stderr, "[cTCP] seqno: %d, ackno: %d, len: %d, flags:",
          ntohl(segment->seqno), ntohl(segment->ackno), ntohs(segment->len));
  if (segment->flags & TH_SYN)
    fprintf(stderr, " SYN");
  if (segment->flags & TH_ACK)
    fprintf(stderr, " ACK");
  if (segment->flags & TH_FIN)
    fprintf(stderr, " FIN");
  /* Keep checksum in network-byte order. */
  fprintf(stderr, ", window: %d, cksum: %x\n",
          ntohs(segment->window), segment->cksum);
}
