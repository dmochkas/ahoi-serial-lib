#include "core.h"

#include <stdio.h>

uint8_t seq_number = 0;

void increment_seq_number() {
    seq_number = (seq_number +1) % 256;
}

void print_packet(const ahoi_packet_t *ahoi_packet) {
    if (ahoi_packet == NULL) {
        printf("ahoi_packet is NULL\n");
        return;
    }

    printf("Ahoi Packet:\n");
    printf("  Source:      %u\n", ahoi_packet->src);
    printf("  Destination: %u\n", ahoi_packet->dst);
    printf("  Type:        %u\n", ahoi_packet->type);
    printf("  Flags:       %u\n", ahoi_packet->flags);
    printf("  Sequence:    %u\n", ahoi_packet->seq);
    printf("  PL Size:     %u\n", ahoi_packet->pl_size);

    if (ahoi_packet->pl_size > 0 && ahoi_packet->payload != NULL) {
        printf("  Payload:     ");
        for (int i = 0; i < ahoi_packet->pl_size; i++) {
            printf("%02x ", ahoi_packet->payload[i]);
        }
        printf("\n");
    }
}