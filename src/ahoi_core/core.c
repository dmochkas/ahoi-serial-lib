#include "core.h"

#include <stdio.h>
#include <string.h>


#include "ahoi_defs.h"
#include "security.h"

static uint8_t seq_number = 0;

void store_key(const uint8_t* new_key) {
    sec_store_key(new_key);
}

uint8_t get_seq_number() {
    return seq_number;
}

void increment_seq_number() {
    seq_number = (seq_number + 1) % 256;
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

packet_decode_status decode_ahoi_packet(const uint8_t *data, const size_t len, ahoi_packet_t* ahoi_packet, ahoi_footer_t* ahoi_footer) {
    if (len < HEADER_SIZE) {
        fprintf(stderr,"Packet too short\n");
        return PACKET_DECODE_KO;
    }

    memcpy(ahoi_packet, data, HEADER_SIZE);

    if (HEADER_SIZE + ahoi_packet->pl_size > len) {
        fprintf(stderr,"Invalid payload size: expected=%d, received=%ld\n",
              ahoi_packet->pl_size, len - HEADER_SIZE);
        return PACKET_DECODE_KO;
    }

    if (ahoi_packet->pl_size) {
        memcpy(ahoi_packet->payload, data + HEADER_SIZE, ahoi_packet->pl_size);
    }

    if (is_footer_carrier(ahoi_packet)) {
        if (HEADER_SIZE + ahoi_packet->pl_size + FOOTER_SIZE > len) {
            fprintf(stderr,"Error extracting footer: expected_size=%d, received_size=%ld\n",
                  HEADER_SIZE + ahoi_packet->pl_size + FOOTER_SIZE, len);
            return PACKET_DECODE_KO;
        }

        memcpy(ahoi_footer, data + HEADER_SIZE + ahoi_packet->pl_size, FOOTER_SIZE);
    }

    if (!is_data_packet(ahoi_packet)) {
        return PACKET_DECODE_OK;
    }

#if SECURE_MODE == 1
    const int16_t ciphertext_len = ahoi_packet->pl_size - TAG_SIZE;

    if (ciphertext_len <= 0) {
        fprintf(stderr,"Impossible to extract a tag from the payload len %d", ahoi_packet->pl_size);
        return PACKET_DECODE_KO;
    }

    if (verify_packet(ahoi_packet) != VERIFY_OK) {
        fprintf(stderr,"Error validating packet\n");
        return PACKET_DECODE_KO;
    }
#endif

    seq_number = ahoi_packet->seq;
    return PACKET_DECODE_OK;
}
