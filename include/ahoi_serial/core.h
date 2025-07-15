#ifndef AHOI_SERIAL_CORE_H
#define AHOI_SERIAL_CORE_H

#include <stdint.h>

#define SECONDS_IN_HOUR 3600

extern uint8_t seq_number;

typedef struct {
    uint8_t src;
    uint8_t dst;
    uint8_t type;
    uint8_t flags;
    uint8_t seq;
    uint8_t pl_size;
    uint8_t* payload;
} ahoi_packet_t;

typedef enum {
    PACKET_GEN_OK,
    PACKET_GEN_KO
} packet_gen_status;

void increment_seq_number();

void print_packet(const ahoi_packet_t *ahoi_packet);

#endif // AHOI_SERIAL_CORE_H
